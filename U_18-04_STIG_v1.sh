#!/bin/bash

    #########################################################
    #This Script will attempt to automate the checking, and later possibly implementing of the Ubuntu 18.04 STIG v1r2. 
    #
    # Jonathan Bennett
    # jonathan.bennett@survice.com
    #   4/27/2020
    #
    # Results where v###### is equal to 1 represent a failure
    # Results where v###### is equal to 2 represent a finding that requires manual checking
    # Results where v###### is equal to 3 represent a partial failure that requires a partial fix
    # Results where v###### is equal to 4 represent an inactive or not runnig process
    #
    # Results from this scan will be usable in creating a remediation script in the future
    #########################################################
filename=scanResults_`date +%Y%m%d%H%M%S`
#V100519 and V-100521
    #Once password on GRUB is in place, changing CLASS in /etc/grub.d/10_Linux 
    # to add "--unrestricted" will allow regular boot to work.
    #This has been added to avoid problems with rebooting after STIG application.
    echo V-100519 |tee -a $filename
    if [[ -e /boot/efi ]] ; then
        grubenc=$(grep -i password /boot/grub/grub.cfg 2>/dev/null | grep -i '^\s*password_pbkdf2')
        if [ -n "${grubenc}" ] ; then
            echo PASS - Grub.cfg contains: "$grubenc" |tee -a $filename
        else
            echo FAIL - There is no encrypted password set in Grub |tee -a $filename
            v100519=1
        fi
    else 
        echo GRUB not installed
    fi
    unset grubenc 

#v100521 
    echo V-100521 |tee -a $filename
    if [[ -e /boot/efi/EFI/grub.cfg ]] ; then
        efienc=$(grep -i password /boot/efi/EFI/grub.cfg 2>/dev/null | grep -i '^\s*password_pbkdf2')
        if [[ (-n ${efienc}) ]] ;then
            echo PASS - EFI Grub.cfg contains: "$efienc" |tee -a $filename
        else
            echo FAIL - There is no encrypted password set in Grub |tee -a $filename
            v100521=1
        fi  
    else
        echo EFI not installed
    fi
    unset efienc


#V100523
    echo V-100523 |tee -a $filename
    grubaud=$(grep -n "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -v "audit=1")
    efiaud=$(grep -n "^\s*linux" /boot/eci/EFI/grub.cfg 2>/dev/null | grep -v "audit=1")
    if [[ -n ${grubaud} || -n ${efiaud} ]] ; then
        echo FAIL - the following lines are currently in grub.cfg and need auditing to be enabled. |tee -a $filename
        echo "$grubaud" "$efiaud" |tee -a $filename
        v100523=1
    else
        echo PASS - Auditing is enabled |tee -a $filename
    fi
    unset grubaud efiaud

#V100525
    echo V-100525 |tee -a $filename
    echo If there is a documented and approved reason for not having data-at-rest encryption, this requirement is Not Applicable. |tee -a $filename
    for i in $(fdisk -l | grep ^/ | awk '{print $1}')
    do 
        if (check1=$(grep $i /etc/crypttab) ); then 
            echo PASS - $i is encrypted |tee -a $filename
        else
            echo FAIL - $i is NOT encrypted |tee -a $filename
            v100525=2
        fi 
    done
    unset i check1

#V100527
    #Enabling a FIPS mode on a pre-existing system involves a number of modifications to the Ubuntu operating system. 
    #Refer to the Ubuntu Server 18.04 FIPS 140-2 security policy document for instructions. 
    #A subscription to the "Ubuntu Advantage" plan is required in order to obtain the FIPS Kernel cryptographic modules and enable FIPS.
    echo V-100527 |tee -a $filename
    if (check1=$(grep -i 1 /proc/sys/crypto/fips_enabled 2>/dev/null) ); then 
        echo Pass - FIPS is enabled |tee -a $filename
    else 
        echo Fail  |tee -a $filename
        v100527=2
    fi
    unset check1

#V100529
    echo V-100529 |tee -a $filename
    if [[ -f /etc/audit/auditd.conf ]] ; then
        action=$(grep "^\s*space_left_action" /etc/audit/auditd.conf | awk '{print $3}')
        limit=$(grep "^\s*space_left " /etc/audit/auditd.conf | awk '{print $3}')
        if ( [[ "$action" =~ [Ee][Mm][Aa][Ii][Ll] ]] ) ; then
            account=$(grep "^\s*action_mail_acct" /etc/audit/auditd.conf | awk '{print $3}')
            echo Manual Check Required - Space_left_action will email ${account} |tee -a $filename
            v100529=2
        else if [[ "$action" == *exec* ]] ; then
                echo Manual Check Required - Please make sure that ${action} notifies the System Administrator. |tee -a $filename
                v100529=2
            else 
                echo Fail space_left_action = $action|tee -a $filename
                v100529=1
            fi
        fi
        if [[ -n $(df -PTh /var/log/audit 2>/dev/null) ]] ; then
            unit=$(df -PTh /var/log/audit 2>/dev/null| grep -v Size | awk '{print substr($3,length($3),1)}')
            size=$(df -PTh /var/log/audit 2>/dev/null| grep -v Size | awk '{print $3}'| cut -d$unit -f1 ) 
            let pct=size/4
            if [[ "$unit" == G ]] ; then 
                let pct=pct*1000
            fi
            if [[ $limit -lt $pct ]] ; then 
                echo "Fail -Space_left: ${limit} is not >= ${pct}.  It needs to be changed in /etc/audit/auditd.conf" |tee -a $filename
                v100529=2
            else
                echo Pass |tee -a $filename
            fi
        fi
    else
        echo Fail |tee -a $filename
        v100529=1
    fi
    unset action account limit size unit pct

#V100531
    echo V-100531 |tee -a $filename
    if [[ -z $(dpkg -s audispd-plugins 2> /dev/null) ]] ; then
        echo "Fail audispd-plugins not installed" |tee -a $filename
        v100531=1
    else
        if [[ $(grep -i active /etc/audisp/plugins.d/au-remote.conf | awk '{print $3}') =~ ["no","NO"] ]]; then
            echo "Fail Remote logging not active" |tee -a $filename
            v100531=3
        else if [[ $(grep -i active /etc/audisp/plugins.d/au-remote.conf | awk '{print $3}') =~ ["yes","YES"] ]]; then
                if [[ -z $(grep -i "^\s*remote_server" /etc/audisp/audisp-remote.conf 2>/dev/null| awk '{print $3}')  ]] ; then
                    echo "Fail No remote server named" |tee -a $filename
                    v100531=3
                else 
                    echo Pass |tee -a $filename
                fi
             fi
        fi
    fi

#V100533
    echo V-100533 |tee -a $filename
    if [[ -f '/etc/cron.weekly/audit-offload' ]]; then
        echo Audit-offload exists.  Verify that it offloads audit logs |tee -a $filename
        v100533=3
    else 
        v100533=2
        echo Manual check required |tee -a $filename
      #  echo Does /etc/crontab include audit data offloading?
      #  echo "$(cat /etc/crontab)"  
      #  while true; do
      #      read -p "(y/n)?" yn
      #      case $yn in
      #          [Yy]* ) echo Pass ; break;;
      #          [Nn]* ) v100533=1;echo Fail; break;;
      #          * ) echo "Please answer yes or no.";;
      #      esac
      #  done
    fi

#V100535
    echo V-100535 |tee -a $filename
    if ( [[ -n $(grep "^AllowUnauthenticated" /etc/apt/apt.conf.d/* | grep -vi "false" ) ]] ) ; then
        echo Fail - AllowUnauthenticated is NOT set to false. |tee -a $filename
        v100535=1
    else
        echo Pass |tee -a $filename
    fi

#V100537
    echo V-100537 |tee -a $filename
    if [[ -z $(grep -i remove-unused-kernel-packages /etc/apt/apt.conf.d/50unattended-upgrades | grep -i "true" | grep -v ^// ) ]] ; then
        echo Remove-Unused-Kernel-Packages is not set to true. |tee -a $filename
        v100537=1
    fi
    if [[ -z $(grep -i remove-unused-dependencies /etc/apt/apt.conf.d/50unattended-upgrades | grep -i "true" | grep -v ^//) ]] ;then
        echo Remove-Unused-Dependencies is not set to true. |tee -a $filename
        v100537=1
    fi
    if [[ -z $( echo "$v100537" ) ]] ; then
    echo Pass |tee -a $filename
    fi


#V100539
    echo V-100539 |tee -a $filename
    if [[ -z $(dpkg -l | grep " nis") ]] ; then 
        echo Pass  |tee -a $filename
    else   
        echo Fail - NIS is installed |tee -a $filename
        v100539=1
    fi
 
#V100541
    echo V-100541 |tee -a $filename
    if [[ -z $(dpkg -l | grep rsh-server) ]] ; then 
        echo Pass  |tee -a $filename
    else   
        echo Fail - rsh-server is installed |tee -a $filename
        v100541=1
    fi
 
#V100545
    echo V-100545 |tee -a $filename
    if [[ $(dpkg -l | grep isectp) ]] ; then 
        if [[ -z $(ps -ef | grep isectpd) ]]; then
        echo Pass |tee -a $filename
        else 
        echo FAIL - isectp is installed but not running |tee -a $filename
        v100545=2
        fi
    else   
        echo FAIL - isectp is not installed |tee -a $filename
        v100545=2
    fi
 
#V100547
    echo V-100547 |tee -a $filename
    if [[ $(dpkg -l | grep rsyslog) ]] ; then
        if [[ $( systemctl is-enabled rsyslog) == "enabled" ]] ; then 
            echo Pass |tee -a $filename
        else    
            echo Fail - rsyslog installed but not enabled |tee -a $filename
            v100547=4
        fi
    else 
        echo Fail - rsyslog is not installed |tee -a $filename
        v100547=1
    fi

#V100549
    echo V-100549 |tee -a $filename
    if [[ $(dpkg -l | grep ufw) ]] ; then 
        echo Pass  |tee -a $filename
    else   
        echo Fail - ufw is not installed |tee -a $filename
        v100541=1
    fi

#V100551
    echo V-100551 |tee -a $filename
    if [[ $(dpkg -s audispd-plugins 2>/dev/null) ]]; then 
        if [[ $(grep -i active /etc/audisp/plugins.d/au-remote.conf| grep yes) ]]; then
                echo If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, this is a finding. |tee -a $filename
                v100551=2
        else 
            echo Fail - au-remote is not active |tee -a $filename
            v100551=4
        fi
    else
        echo Fail audispd-plugins not installed |tee -a $filename
        v100551=1
    fi

#V100553
    echo V-100553 |tee -a $filename
    if [[ -n /etc/sssd/sssd.conf ]] ; then
        echo Not Applicable |tee -a $filename
    else
        if [[ $(grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | awk -F= '{print $2}') == 1 ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100553=1
        fi
    fi

#V100555
    echo V-100555 |tee -a $filename
    if [[ -n $( grep pam_faildelay /etc/pam.d/common-auth | grep -v ^\s*\# ) ]] ; then
        if [[ $(grep pam_faildelay /etc/pam.d/common-auth | awk -F= '{print $2}' ) -ge 4000000  ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail 3|tee -a $filename
            v100555=3
        fi
    else
        echo Fail 1|tee -a $filename
        v100555=1
    fi

#V100557
    echo V-100557 |tee -a $filename
    if ( [[ $( grep pam_lastlog /etc/pam.d/login) =~ required ]] && ! [[ $( grep pam_lastlog /etc/pam.d/login) =~ silent ]] ) ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100557=1
    fi

#V100559
    echo V-100559 |tee -a $filename
    if [[ -n $(grep pam_tally2 /etc/pam.d/common-auth) ]] ; then
        if ( [[ $( grep pam_tally2 /etc/pam.d/common-auth) =~ 'onerr=fail' ]] && [[ $( grep pam_tally2 /etc/pam.d/common-auth | awk -F'deny=' '{print$2}' ) == 3 ]] ) ; then
            echo  Pass |tee -a $filename
        else
            echo Fail 3 |tee -a $filename
            v100559=3
        fi
    else
        echo Fail 1| tee -a $filename
        v100559=1
    fi

#V100561
    echo V-100561 |tee -a $filename
    if ! [[ $(dpks -s dconf 2>/dev/null) ]] ; then 
        echo Not-Applicable |tee -a $filename
    else 
        if [[ $(grep banner-message-enable /etc/gdm3/greeter.dconf-defaults | awk -F= '{print $2}') == 'true' ]] ; then 
            if [[  $(grep banner-message-text /etc/gdm3/greeter.dconf-defaults) == "banner-message-text='You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'" ]] ; then
                echo Pass |tee -a $filename
            else
                message=$(grep banner-message-text /etc/gdm3/greeter.dconf-defaults)
                echo Fail  |tee -a $filename
                echo $message |tee -a $filename
                v100561=2
            fi
        else
            echo Fail |tee -a $filename
            v100561=1
        fi
    fi

#V100563
    echo V-100563 |tee -a $filename
    if [[ $(passwd -S root | awk '{print $2}') == L ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100563=1
    fi
    
#V100565
    echo V-100565 |tee -a $filename
    v100565=2
    echo Manual Check - Verify that the sudo group has only members who should have access to security functions.  |tee -a $filename
    members=$(grep sudo /etc/group)
    echo $members |tee -a $filename
    unset members

#V100567
    echo V-100567 |tee -a $filename
    read -d '"EOF"' bannerText << EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
    if ( [[ $(grep -i banner /etc/ssh/sshd_config) =~ '/etc/issue' ]] && ! [[ $(grep -i 'Banner /etc/issue' /etc/ssh/sshd_config) =~ ^\# ]] ) ; then 
        if [[ -z $(diff <(cat /etc/issue) <(echo "$bannerText") ) ]] ; then
            echo Banner matches |tee -a $filename
        else
            echo Fail - Correct banner not set. |tee -a $filename
            v100567=3
        fi
    else
        echo Fail |tee -a $filename
        v100567=1
    fi
    unset bannerText

#V100569
    echo V-100569 |tee -a $filename
    if [[ $( grep pam_tally2 /etc/pam.d/common-auth | awk -F'deny=' '{print$2}' ) == 3 ]] ; then
        echo Pass |tee -a $filename
    else 
        echo Fail |tee -a $filename
        v100569=1
    fi

#V100571
    echo V-100571 |tee -a $filename
    if [[ $(grep -i "^ucredit" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -lt '0' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100571=1
    fi

#V100573
    echo V-100573 |tee -a $filename
    if [[ $(grep -i "^lcredit" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -lt '0' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100573=1
    fi

#V100575
    echo V-100575 |tee -a $filename
    if [[ $(grep -i "^dcredit" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -lt '0' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100575=1
    fi

#V100577
    echo V-100577 |tee -a $filename
    if [[ $(grep -i "^difok" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -ge '8' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100577=1
    fi

#V100579
    echo V-100579 |tee -a $filename
    if [[ $( grep -i ^encrypt_method /etc/login.defs | awk '{print $2}' ) == SHA512 ]] ; then 
        echo Pass |tee -a $filename
    else
        echo Manual check required - Minimum SHA512  |tee -a $filename
        grep -i ^encrypt_method /etc/login.defs |tee -a $filename
        v100579=2
    fi

#V100581
    echo V-100581 |tee -a $filename
    if [[ -z $( dpkg -l telnetd 2>/dev/null ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100581=1
    fi

#V100583
    echo V-100583 |tee -a $filename
    if( ! [[ -z $( grep -i ^pass_min_days /etc/login.defs) ]] && [[ $( grep -i ^pass_min_days /etc/login.defs | awk '{print $2}' ) -ge 1 ]] ) ; then 
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100583=1
    fi

#V100585
    echo V-100585 |tee -a $filename
    if ( ! [[ -z $( grep -i ^pass_max_days /etc/login.defs ) ]] && [[ $( grep -i ^pass_max_days /etc/login.defs | awk '{print $2}' ) -le 60 ]] ) ; then 
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100585=1
    fi

#V100587
    echo V-100587 |tee -a $filename
    if ! [[ -z $( grep -i remember /etc/pam.d/common-password ) ]] ; then
        if ! [[ $( grep -i remember /etc/pam.d/common-password | grep ^\#) ]] ; then
            if [[ $( grep pam.unix.so /etc/pam.d/common-password | awk  -F'[=\t ]' '{ for(i=1;i<=NF;i++) if ($i == "remember") print $(i+1) }' ) -ge 5 ]] ; then
                echo Pass |tee -a $filename
            else
                echo Fail - remember value too low |tee -a $filename
                v100587=3
            fi
        else
            echo Fail - no active remember value |tee -a $filename
            v100587=1
        fi
    else
        echo Fail - no remember entry |tee -a $filename
        v100587=1
    fi

#V100589
    echo V-100589 |tee -a $filename
    if [[ $(grep -i "^minlen" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -ge '15' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100589=1
    fi

#V100591
    echo V-100591 |tee -a $filename
    if [[ -n $( grep -i pam_unix.so /etc/pam.d/common-password | grep -i 'sha512' ) ]] ; then
        if [[ $( grep -i ^encrypt_method /etc/login.defs | awk '{print $2}' ) == SHA512 ]] ; then 
            echo Pass |tee -a $filename
        else
            echo Manual check required - Minimum SHA512  |tee -a $filename
            grep -i ^encrypt_method /etc/login.defs
            #v100591=2
        fi
    else
        echo Fail - SHA512 is not selected |tee -a $filename
        #v100591=2
    fi

#V100593
    echo V-100593 |tee -a $filename
    echo A policy must exist that ensures when a user account is created, it is created using a method that forces a user to change their password upon their next login. |tee -a $filename
    echo Potential methods to force a user to change their password include "chage -d 0 [UserName]" or "passwd -e [UserName]" |tee -a $filename

#V100595
    echo V-100595 |tee -a $filename
    if [[ $( grep -i "^dictcheck" /etc/security/pwquality.conf | awk -F'= ' '{print $2}' ) == '1' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100595=1
    fi

#V100597
    echo V-100597 |tee -a $filename
    if [[ -z $( egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* ) ]] ; then 
        echo Pass |tee -a $filename
    else 
        echo Fail |tee -a $filename
        v100597=1
        $( egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/* ) |tee -a $filename
    fi

#V100599
    echo V-100599 |tee -a $filename
    if [[ $(dpkg -l libpam-pwquality 2>/dev/null) ]] ; then
        if [[ $( grep -i ^enforcing /etc/security/pwquality.conf | awk -F' = ' '{print $2}') == '1' ]] ; then
            if [[ $(grep pam.pwquality.so /etc/pam.d/common-password | awk  -F'[=\t ]' '{ for(i=1;i<=NF;i++) if ($i == "retry") print $(i+1) }' ) == [123] ]] ; then
                echo Pass |tee -a $filename
            else
                echo Fail - no or incorrect settings in pam configuration |tee -a $filename
                v100599=3
            fi
        else 
            echo Fail - pwquality not enforcing |tee -a $filename
            v100599=4
        fi
    else
        echo Fail - libpam-pwquality not installed |tee -a $filename
        v100599=1
    fi

#V100601
    echo V-100601 |tee -a $filename
    if [[ -z $(find / -type d -perm -002 ! -perm -1000) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail - incorrent permissions on world writable directories |tee -a $filename
        v100601=1
    fi

#V100603
    echo V-100603 |tee -a $filename
    if [[ -z $( find /var/log -perm /137 -type f -exec stat -c "%n %a" {} \; ) ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - incorrect permissions on system log files |tee -a $filename
        v100603=1
    fi

#V100605
    echo V-100605 |tee -a $filename
    if [[ $(stat -c "%G" /var/log ) == 'syslog' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log not group owned by syslog |tee -a $filename
        v100605=1
    fi

#V100607
    echo V-100607 |tee -a $filename
    if [[ $(stat -c "%U" /var/log ) == 'root' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log not owned by root |tee -a $filename
        v100607=1
    fi

#V100609
    echo V-100609 |tee -a $filename
    if [[ $(stat -c "%a" /var/log ) == '750' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log does not have the right permissions |tee -a $filename
        v100609=1
    fi

#V100611
    echo V-100611 |tee -a $filename
    if [[ $(stat -c "%G" /var/log/syslog ) == 'adm' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log/syslog not group owned by adm |tee -a $filename
        v100611=1
    fi

#V100613
    echo V-100613 |tee -a $filename
    if [[ $(stat -c "%U" /var/log/syslog ) == 'syslog' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log/syslog not owned by syslog |tee -a $filename
        v100613=1
    fi

#V100615
    echo V-100615 |tee -a $filename
    if [[ $(stat -c "%a" /var/log/syslog ) == '640' ]]; then
        echo Pass |tee -a $filename
    else
        echo Fail - /var/log/syslog does not have the right permissions |tee -a $filename
        v100615=1
    fi

#V100617
    echo V-100617 |tee -a $filename
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if [[ $(stat -c "%a" $i 2>/dev/null ) == '755' ]]; then
                echo Pass $i |tee -a $filename
            else
                echo Fail $i - verify $(stat -c "%a" $i 2>/dev/null ) is less permissive than 755 |tee -a $filename
                v100617=1
            fi
        else 
            echo Fail - $i does not exist |tee -a $filename
            v100617=1
        fi
    done
    unset i

#V100619
    echo V-100619 |tee -a $filename
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if [[ $(stat -c "%U" $i 2>/dev/null ) == 'root' ]]; then
                echo Pass $i |tee -a $filename
            else
                echo Fail $i is not owned by root |tee -a $filename
                v100619=1
            fi
        else
            echo Fail - $i does not exist |tee -a $filename
            v100617=1
        fi
    done
    unset i

#V100621
    echo V-100621 |tee -a $filename
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if [[ $(stat -c "%G" $i 2>/dev/null ) == 'root' ]]; then
                echo Pass $i |tee -a $filename
            else
                echo Fail $i is not group owned by root |tee -a $filename
                v100621=1
            fi
        else
            echo Fail - $i does not exist |tee -a $filename
            v100621=1
        fi
    done
    unset i

#V100623
    echo V-100623 |tee -a $filename
    if [[ -z $( find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c " %a" '{}' \; ) ]] ; then 
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100623=1
    fi

#V100625
    echo V-100625 |tee -a $filename
    if [[ -z $( find /lib /lib64 /usr/lib -perm /022 -type d -exec stat -c " %a" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100625=1
    fi

#V100627
    echo V-100627 |tee -a $filename
    if [[ -z $( find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c " %U" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100627=1
    fi

#V100629
    echo V-100629 |tee -a $filename
    if [[ -z $( find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c " %U" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100629=1
    fi

#V100631
    echo V-100631 |tee -a $filename
    if [[ -z $( find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail  |tee -a $filename
        v100631=1
    fi

#V100633
    echo V-100633 |tee -a $filename
    if [[ -z $( find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c " %G" '{}' \; ) ]] ; then
        echo Pass  |tee -a $filename
    else
        echo Fail  |tee -a $filename
        v100633=1
    fi

#V100635
    echo V-100635 |tee -a $filename
    if [[ -z $(find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c " %a" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail - incorrect permissions on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c " %a" '{}' \; |tee -a $filename
        v100635=1
    fi

#V100637
    echo V-100637 |tee -a $filename
    if [[ -z $(find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c " %a" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail incorrect permissions on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c " %a" '{}' \;  |tee -a $filename
        v100637=1
    fi

#V100639
    echo V-100639 |tee -a $filename
    if [[ -z $( find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c " %U" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail - incorrect ownership on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c " %U %F" '{}' \;  |tee -a $filename
        v100639=1
    fi

#V100641
    echo V-100641 |tee -a $filename
    if [[ -z $( find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c " %U" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else 
        echo Fail - incorrect ownership on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c " %U %F" '{}' \;  |tee -a $filename
        v100641=1
    fi

#V100643
    echo V-100643 |tee -a $filename
    if [[ -z $( find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec stat -c " %G" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else 
        echo Fail - incorrect ownership on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec stat -c " %n %G %F" '{}' \;  |tee -a $filename
        v100643=1
    fi

#V100645
    echo V-100645 |tee -a $filename
    if [[ -z $( find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c " %G" '{}' \; ) ]] ; then
        echo Pass |tee -a $filename
    else 
        echo Fail - incorrect ownership on: |tee -a $filename
        find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c " %G %F" '{}' \;  |tee -a $filename
        v100645=1
    fi

#V100647
    echo V-100647 |tee -a $filename
    if [[ $( grep -i "^ocredit" /etc/security/pwquality.conf | awk -F= '{print $2}' ) -lt '0' ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100647=1
    fi

#V100649
    echo V-100649 |tee -a $filename
    if ! [[ -e /etc/dconf ]] ; then
        echo Pass |tee -a $filename
    else
        if [[ -z $(grep logout /etc/dconf/db/local.d/* 2>/dev/null) || -z $(grep logout /etc/dconf/db/local.d/* 2>/dev/null | awk -F= '{print $2}')   ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail - Ctrl-Alt-Delete sequence for the graphical user interface is not disabled |tee -a $filename
            v100649=1
        fi
    fi

#V100651
    echo V-100651 |tee -a $filename
    if [[ $( systemctl is-active ctrl-alt-del.target) != "active" ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100651=1
    fi

#V100653
    echo V-100653 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $( auditctl -l | grep tallylog ) =~ "-w /var/log/tallylog -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100653=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100653=1
    fi

#V100655
    echo V-100655 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep faillog ) =~ "-w /var/log/faillog -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100655=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100655=1
    fi

#V100657
    echo V-100657 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep lastlog ) =~ "-w /var/log/lastlog -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100657=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100657=1
    fi

#V100659
    echo V-100659 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep sudo.log ) =~ "-w /var/log/sudo.log -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100659=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100659=1
    fi

#V100661
    echo V-100661 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/var/log/wtmp' ) =~ "-w /var/log/wtmp -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100661=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100661=1
    fi

#V100663
    echo V-100663 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/var/run/wtmp' ) =~ "w /var/run/wtmp -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100663=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100663=1
    fi

#V100665
    echo V-100665 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/var/log/btmp' ) =~ "-w /var/log/btmp -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100665=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100665=1
    fi

#V100667
    echo V-100667 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'passwd' ) =~ "-w /etc/passwd -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100667=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100667=1
    fi

#V100669
    echo V-100669 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'group' ) =~ "-w /etc/group -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100669=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100669=1
    fi

#V100671
    echo V-100671 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'gshadow' ) =~ "-w /etc/gshadow -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100671=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100671=1
    fi

#V100673
    echo V-100673 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'shadow' ) =~ "-w /etc/shadow -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100673=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100673=1
    fi

#V100675
    echo V-100675 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'opasswd' ) =~ "-w /etc/security/opasswd -p wa" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100675=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100675=1
    fi

#V100677
    echo V-100677 |tee -a $filename
    if [[ $(dpkg -l | grep auditd) ]] ; then
        if [[ $(systemctl is-enabled auditd.service) == "enabled" ]] ; then 
            if [[ $(systemctl is-active auditd.service) == "active" ]] ; then 
                echo Pass |tee -a $filename
            else    
                echo Fail - auditd inactive |tee -a $filename
                v100677=4
            fi
        else    
            echo Fail - auditd installed but not enabled |tee -a $filename
            v100677=4
        fi
    else 
        echo Fail - auditd is not installed |tee -a $filename
        v100677=1
    fi

#V100679
    echo V-100679 |tee -a $filename
    if [[ -n $( grep ^\s*action_mail_acct /etc/audit/auditd.conf) ]] ; then
        if [[ $( grep ^\s*action_mail_acct /etc/audit/auditd.conf | awk '{print $3}') == 'root' ]] ; then
            echo Pass |tee -a $filename
        else 
            account=$(grep ^\s*action_mail_acct /etc/audit/auditd.conf | awk '{print $3}')
            echo Manual Check Required - Space_left_action will email ${account} |tee -a $filename
            v100679=2
        fi
    else
        echo Fail - action_mail_acct not set | tee $filename
        v100679=1
    fi

#V100681
    echo V-100681 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then
        if [[ -n $(grep ^disk_full_action /etc/audit/auditd.conf 2>/dev/null) ]] ; then
            action=$(grep disk_full_action /etc/audit/auditd.conf | awk '{print $3}')
            if ( [[ "$action" =~ (HALT|SYSLOG|SINGLE) ]] ) ; then
                echo Pass |tee -a $filename
            else 
                echo Fail |tee -a $filename
                v100681=3
            fi
        else
            echo Fail |tee -a $filename
            v100681=1
        fi
    else
        echo Fail |tee -a $filename
        v100681=1
    fi

    unset action 

#V100683
    echo V-100683 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $( stat -c "%a" $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) == '600' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100683=1
        fi
    else
        echo Fail |tee -a $filename
        v100683=1
    fi

#V100685
    echo V-100685 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $(stat -c "%U" $(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) == 'root' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100685=1
        fi
    else
        echo Fail |tee -a $filename
        v100685=1
    fi
   
#V100687
    echo V-100687 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $(stat -c "%G" $(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) == 'root' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100687=1
        fi
    else
        echo Fail |tee -a $filename
        v100687=1
    fi

#V100689
    echo V-100689 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $(stat -c "%a" $(dirname $(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) ) == '750' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100689=1
        fi
    else
        echo Fail |tee -a $filename
        v100689=1
    fi

#V100691
    echo V-100691 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $(stat -c "%U" $(dirname $(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) ) == 'root' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100691=1
        fi
    else
        echo Fail |tee -a $filename
        v100691=1
    fi
   
#V100693
    echo V-100693 |tee -a $filename
    if [[ -e /etc/audit/auditd.conf ]] ; then 
        if [[ $(stat -c "%G" $(dirname $(grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) ) == 'root' ]]; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100693=1
        fi
    else
        echo Fail |tee -a $filename
        v100693=1
    fi

#V100695
    echo V-100695 |tee -a $filename
    if [[ -e /etc/audit/ ]] ; then
        for i in $(stat -c "" /etc/audit/audit.rules /etc/audit/rules.d/* /etc/audit/auditd.conf 2>/dev/null) ; 
        do
            if [[ $(stat -c "%a" $i) == '640' ]] ; then
                echo Pass |tee -a $filename
            else 
                echo Fail - $i permissions are $(stat -c "%a" $i) |tee -a $filename
                v100695=1
            fi
        done
    else
        echo Fail - /etc/audit does not exist |tee -a $filename
        v100695=1
    fi
    unset i

#V100697
    echo V-100697 |tee -a $filename
    if [[ -e /etc/audit/ ]] ; then
        for i in $(stat -c "" /etc/audit/audit.rules /etc/audit/rules.d/* /etc/audit/auditd.conf 2>/dev/null) ; 
        do
            if [[ $(stat -c "%G" $i) == 'root' ]] ; then
                echo Pass |tee -a $filename
            else 
                echo Fail - $i permissions are $(stat -c "%a" $i) |tee -a $filename
                v100697=1
            fi
        done
    else
        echo Fail - /etc/audit does not exist |tee -a $filename
        v100697=
    fi
    unset i

#V100699
    echo V-100699 |tee -a $filename
    if [[ -e /etc/audit/ ]] ; then
        for i in $(stat -c "" /etc/audit/audit.rules /etc/audit/rules.d/* /etc/audit/auditd.conf 2>/dev/null) ; 
        do
            if [[ $(stat -c "%G" $i) == 'root' ]] ; then
                echo Pass |tee -a $filename
            else 
                echo Fail - $i permissions are $(stat -c "%a" $i) |tee -a $filename
                v100699=1
            fi
        done
    else
        echo Fail - /etc/audit does not exist |tee -a $filename
        v100699=1
    fi
    unset i

#V100701
    echo V-100701 |tee -a $filename
    if [[ -n $( dirname $(grep ^log_file /etc/audit/auditd.conf 2>/dev/null | awk -F' = ' '{print $2}' ) 2>/dev/null ) ]] ; then 
    folder=$(dirname $(grep ^log_file /etc/audit/auditd.conf 2>/dev/null | awk -F' = ' '{print $2}' ) 2>/dev/null )
        if [[ -n "$folder" ]] ; then
            mountPoint=$(df -h $folder | grep ^/dev/ | awk '{print $NF}' )
            partSize=$(df -h $folder | grep ^/dev/ | awk '{print $2}' )
            size=$( echo $partSize | grep -o '.$')
            if [[ $mountPoint == $folder ]] ; then 
                if ( [[ $size == G ]] && [[ ${partSize::-1} -ge 10 ]] ) ; then
                echo Pass |tee -a $filename
                else 
                echo Fail - $mountPoint is $partSize and should be at least 10G |tee -a $filename
                v100701=3
                fi
            else 
                partFree=$(df -h $folder | grep ^/dev/ | awk '{print $4}' )
                if (( $(echo "${partFree::-1} > 10" | bc -l) )) ; then
                echo Pass |tee -a $filename
                else
                echo "Fail - there may be insufficient space on $mountPoint for audit logs -- $partFree space available" |tee -a $filename
                v100701=2
                fi
            fi
        else
            echo Fail - Folder listed in audit.conf does not exist |tee -a $filename
            v100701=1
        fi
    else
        echo Fail - Audit.conf does not exist |tee -a $filename
        v100701=1
    fi
    #echo $folder $mountPoint $partSize $size $partFree $v100701
    unset folder mountPoint partSize size partFree

#V100703
    echo V-100703 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if ( [[  $( auditctl -l | grep '/bin/su ') =~ "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295" ]] || [[  $( grep '/bin/su ' /etc/audit/rules.d/stig.rules) =~ "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295" ]] ) ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100703=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100703=1
    fi

#V100705
    echo V-100705 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/chfn' ) =~ "-a always,exit -S all -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100705=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100705=1
    fi

#V100707
    echo V-100707 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/bin/mount' ) =~ "-a always,exit -S all -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100707=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100707=1
    fi

#V100709
    echo V-100709 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/bin/umount' ) =~ "-a always,exit -S all -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100709=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100709=1
    fi

#V100711
    echo V-100711 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/ssh-agent' ) =~ "-a always,exit -S all -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100711=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100711=1
    fi

#V100713
    echo V-100713 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'ssh-keysign' ) =~ "-a always,exit -S all -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100713=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100713=1
    fi

#v100715
    echo V-100715 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -F key=perm_mod
EOF
        if  [[ -z $(diff <(echo "$( auditctl -l | grep ' setxattr' | grep perm_mod)") <(echo "$value") ) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100715=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100715=1
    fi
    unset value

#v100717
    echo V-100717 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F key=perm_mod
EOF
        if [[ -z $(diff <(echo "$( auditctl -l | grep lsetxattr | grep perm_mod )") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100717=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100717=1
    fi
    unset value

#v100719
    echo V-100719 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F key=perm_mod
EOF
        if [[ -z $(diff <(echo "$( auditctl -l | grep fsetxattr | grep perm_mod)" ) <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100719=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100719=1
    fi
    unset value

#v100721
    echo V-100721 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F key=perm_mod
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep lremovexattr | grep perm_mod)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100721=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100721=1
    fi
    unset value

#v100723
    echo V-100723 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -F key=perm_mod
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep fremovexattr | grep perm_mod)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100723=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100723=1
    fi
    unset value

#V100725
    echo V-100725 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' chown ' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100257=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100725=1
    fi    
    unset value
     
#v100727
    echo V-100727 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep 'fchown ' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100727=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100727=1
    fi
    unset value

#v100729
    echo V-100729 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep fchownat | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100729=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100729=1
    fi
    unset value

#v100731
    echo V-100731 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep lchown | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100731=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100731=1
    fi
    unset value

#v100733
    echo V-100733 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' chmod' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100733=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100733=1
    fi
    unset value

#v100735
    echo V-100735 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep 'fchmod ' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100735=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100735=1
    fi
    unset value

#v100737
    echo V-100737 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep fchmodat | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100737=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100737=1
    fi
    unset value

#v100739
    echo V-100739 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep 'open ' | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100739=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100739=1
    fi
    unset value

#v100741
    echo V-100741 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' truncate' | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100741=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100741=1
    fi
    unset value

#v100743
    echo V-100743 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ftruncate | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100743=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100743=1
    fi
    unset value
   
#v100745
    echo V-100745 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep creat | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100745=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100745=1
    fi
    unset value
     
#v100747
    echo V-100747 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep openat | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100747=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100747=1
    fi
    unset value
    
#v100749
    echo V-100749 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep open_by_handle_at | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100749=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100749=1
    fi
    unset value
    
#V100751
    echo V-100751 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/sudo ' ) =~ "-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100751=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100751=1
    fi

#V100753
    echo V-100753 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/sudoedit' ) =~ "-a always,exit -S all -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100753=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100753=1
    fi

#V100755
    echo V-100755 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/chsh' ) =~ "-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100755=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100755=1
    fi

#V100757
    echo V-100757 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/newgrp' ) =~ "-a always,exit -S all -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100757=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100757=1
    fi

#V100759
    echo V-100759 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/chcon' ) =~ "-a always,exit -S all -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100759=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100759=1
    fi

#V100761
    echo V-100761 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'apparmor_parser' ) =~ "-a always,exit -S all -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100761=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100761=1
    fi

#V100763
    echo V-100763 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $( auditctl -l | grep '/usr/bin/setfacl' ) =~ "-a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100763=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100763=1
    fi

#V100765
    echo V-100765 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $( auditctl -l | grep '/usr/bin/chacl' ) =~ "-a always,exit -S all -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100765=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100765=1
    fi

#V100767
    echo V-100767 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $( auditctl -l | grep '/usr/bin/passwd' ) =~ "-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100767=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100767=1
    fi

#V100769
    echo V-100769 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/sbin/unix_update' ) =~ "-a always,exit -S all -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100769=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100769=1
    fi

#V100771
    echo V-100771 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/gpasswd' ) =~ "-a always,exit -S all -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100771=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100771=1
    fi

#V100773
    echo V-100773 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/bin/chage' ) =~ "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100773=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100773=1
    fi

#V100775
    echo V-100775 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/sbin/usermod') =~ "-a always,exit -S all -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100775=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100775=1
    fi

#V100777
    echo V-100777 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep '/usr/sbin/pam_timestamp_check') =~ "-a always,exit -S all -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100777=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100777=1
    fi

#v100779
    echo V-100779 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=-1 -F key=module_chng
EOF
        if [[ -z $( diff <( echo "$(auditctl -l | grep ' init_module' | grep module_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100779=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100779=1
    fi
    unset value
    
#v100781
    echo V-100781 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=-1 -F key=module_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep finit_module | grep module_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100781=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100781=1
    fi
    unset value
    
#v100783
    echo V-100783 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -F key=module_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep delete_module | grep module_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100783=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100783=1
    fi
    unset value

#v100785
    echo V-100785 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv
-a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv
-a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv
EOF
        if [[ -z $( diff <( echo "$(auditctl -l | grep execve | grep execpriv)") <( echo "$value" ) 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100785=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100785=1
    fi
    unset value
    
#v100787
    echo V-100787 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' setxattr' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100787=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100787=1
    fi
    unset value
    
#v100789
    echo V-100789 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep lsetxattr | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100789=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100789=1
    fi
    unset value
    
#v100791
    echo V-100791 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep fsetxattr | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100791=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100791=1
    fi
    unset value
    
#v100793
    echo V-100793 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' removexattr' | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100793=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100793=1
    fi
    unset value
    
#v100795
    echo V-100795 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_chng
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep lremovexattr | grep perm_chng)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100795=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100795=1
    fi
    unset value
    
#v100797
    echo V-100797 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S unlink -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=-1 -F key=delete
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep 'unlink ' | grep delete)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100797=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100797=1
    fi
    unset value
    
#v100799
    echo V-100799 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=-1 -F key=delete
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep unlinkat | grep delete)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100799=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100799=1
    fi
    unset value
    
#v100801
    echo V-100801 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=-1 -F key=delete
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep 'rename ' | grep delete)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100801=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100801=1
    fi
    unset value
    
#v100803
    echo V-100803 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b64 -S renameat -F auid>=1000 -F auid!=-1 -F key=delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=-1 -F key=delete
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep renameat | grep delete)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100803=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100803=1
    fi
    unset value

#v100805
    echo V-100805 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S init_module,finit_module -F key=modules
-a always,exit -F arch=b64 -S init_module,finit_module -F key=modules
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep -E 'init_module|finit_module' | grep modules)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100805=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100805=1
    fi
    unset value

#v100807
    echo V-100807 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S delete_module -F key=modules
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep delete_module | grep modules)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100807=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100807=1
    fi
    unset value

#v100809
    echo V-100809 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' truncate' | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100809=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100809=1
    fi
    unset value

#v100811
    echo V-100811 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ftruncate | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100811=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100811=1
    fi
    unset value

#v100813
    echo V-100813 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=perm_access
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep creat | grep perm_access)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100813=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100813=1
    fi
    unset value

#v100815
    echo V-100815 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S init_module,finit_module -F key=modules
-a always,exit -F arch=b64 -S init_module,finit_module -F key=modules
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep -E 'init_module|finit_module' | grep modules)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100815=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100815=1
    fi
    unset value

#v100817
    echo V-100817 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S delete_module -F key=modules
-a always,exit -F arch=b64 -S delete_module -F key=modules
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep -E delete_module | grep modules)") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100817=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100817=1
    fi
    unset value

#V100819
    echo V-100819 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep "/sbin/modprobe" ) =~ "-w /sbin/modprobe -p x" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100819=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100819=1
    fi

#V100821
    echo V-100821 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep 'kmod' ) =~ "-w /bin/kmod -p x" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100821=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100821=1
    fi

#V100823
    echo V-100823 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep fdisk) =~ "-w /bin/fdisk -p x" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100823=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100823=1
    fi

#V100825
    echo V-100825 |tee -a $filename
    if [[  -n $( grep '^* hard maxlogins' /etc/security/limits.conf | awk '{print $NF}' ) ]] ; then
        number="$( grep '^* hard maxlogins' /etc/security/limits.conf | awk '{print $NF}' )"
        if [[ $number -le 10 ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100825=3
        fi
    else 
        echo Fail |tee -a $filename
        v100825=1
    fi

#V100827
    echo V-100827 |tee -a $filename
    if ! [[ $(dpks -s dconf 2>/dev/null) ]] ; then 
        echo Not-Applicable |tee -a $filename
    else 
        if [[ $(gsettings get org.gnome.desktop.screensaver lock-enabled) == 'true' ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100827=1
        fi
    fi

#V100829
    echo V-100829 |tee -a $filename
    if [[ -e "/etc/profile.d/autologout.sh" ]] ; then
        read -d '"EOF"' value << EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF
        if [[ -z $(diff $(/etc/profile.d/autologout.sh) <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100829=1
        fi
    else
        echo Fail |tee -a $filename
        v100829=1
    fi
    unset value

#V100831
    echo V-100831 |tee -a $filename
    if [[ -n $(dpkg -l | grep vlock) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100831=1
    fi

#V100833
    echo V-100833 |tee -a $filename
    c=$( grep -i "^\s*ClientAliveInterval" /etc/ssh/sshd_config | awk '{print $2}')
    if [[ ((-n "$c")) &&  (("$c" -le '600')) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100833=1
    fi
    unset c

#V100835
    echo V-100835 |tee -a $filename
    if [[ -n $(grep -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*) ]] ; then 
        echo Pass |tee -a $filename
    else 
        echo Fail |tee -a $filename
        v100835=1
    fi

#V100837
    echo V-100837 |tee -a $filename
    if [[ -z $( grep -E '^Ciphers ' /etc/ssh/sshd_config | awk '{n=split($2, a, ","); for (i=1; i<=n; i++) print a[i] }' | grep -v ^aes ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100837=1
    fi

#V100839
    echo V-100839 |tee -a $filename
    if [[ -n $( grep -i "^\s*Protocol\s*2" /etc/ssh/sshd_config) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100839=1
    fi

#V100841
    echo V-100841 |tee -a $filename
    if [[ -n $( grep -i "^\s*UsePAM\s*yes" /etc/ssh/sshd_config ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100841=1
    fi

#V100843
    echo V-100843 |tee -a $filename
    if [[ -n $( grep -i "^\s*ClientAliveCountMax\s*1" /etc/ssh/sshd_config) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100843=1
    fi

#V100845
    echo V-100845 |tee -a $filename
    if [[ -n $( grep -i "^\s*ClientAliveInterval\s*600" /etc/ssh/sshd_config) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100845=1
    fi

#V100847
    echo V-100847 |tee -a $filename
    if [[ -z $( grep -i '^\s*macs ' /etc/ssh/sshd_config | awk '{n=split($2, a, ",")
     for (i=1; i<=n; i++) if ( ! ((a[i] == "hmac-sha2-256") || ( a[i] == "hmac-sha2-512")) ) {print a[i]} }' ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100847=1
    fi

#V100849
    echo V-100849 |tee -a $filename
    if [[ ( $(dpkg -l | grep openssh | awk '{print $2}' ) =~ openssh-server ) ]] ; then
        if [[ $(systemctl status sshd.service | egrep -i "(active: active|loaded: loaded)" | awk '{print $2}' ) =~ loaded &&
            $(systemctl status sshd.service | egrep -i "(active: active|loaded: loaded)" | awk '{print $2}' ) =~ active ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100849=3
        fi
    else
        echo Fail |tee -a $filename
        v100849=1
    fi

#V100851
    echo V-100851 |tee -a $filename
    if [[ ( $(egrep '(^\s*PermitEmptyPasswords)' /etc/ssh/sshd_config) =~ no ) && ($(egrep '(^\s*PermitUserEnvironment)' /etc/ssh/sshd_config) =~ no ) ]] ; then 
        echo Pass |tee -a $filename
    else 
        echo Fail |tee -a $filename
        v100851=1
    fi 

#V100853
    echo V-100853 |tee -a $filename
    if [[ -n $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        if [[ $(grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf ) =~ 'opensc' ]] ; then
            if [[ -n $(awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca) ]] ; then
                echo Pass |tee -a $filename
            else 
                echo Fail |tee -a $filename
                v100853=2
            fi
        else 
            echo Fail |tee -a $filename
            v100853=2
        fi
    else
        echo Fail  |tee -a $filename
        v100853=2
    fi

#V100855
    echo V-100855 |tee -a $filename
    if [[ $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        if [[ $( grep '^\s*use_mappers' /etc/pam_pkcs11/pam_pkcs11.conf | awk '{print $2}') == 'pwent' ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100855=2
        fi
    else
        echo Fail |tee -a $filename
        v100855=2
    fi

#V100857
    echo V-100857 |tee -a $filename
    if [[ $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        if [[ -n $(grep pam_pkcs11.so /etc/pam.d/common-auth ) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100857=2
    fi
    else 
        echo Fail |tee -a $filename
        v100857=2
    fi

#V100859
    echo V-100859 |tee -a $filename
    if [[ -n $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100859=2
    fi

#V100861
    echo V-100861 |tee -a $filename
    if [[ -n $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100861=2
    fi
        
#V100863
    echo V100863 |tee -a $filename
    if [[ -n $(dpkg -l | grep libpam-pkcs11 ) ]] ; then
        if [[ $(grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf ) =~ 'opensc' ]] ; then
            if [[ -n $(awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on) ]] ; then
                echo Pass |tee -a $filename
            else 
                echo Fail |tee -a $filename
                v100863=2
            fi
        else 
            echo Fail |tee -a $filename
            v100863=2
        fi
    else
        echo Fail  |tee -a $filename
        v100863=2
    fi

#V100865
    echo V-100865 |tee -a $filename
    echo Manual Check |tee -a $filename
    #The Ubuntu operating system must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions.
    v100865=2

#V100867
    echo V-100867 |tee -a $filename
    if [[ -n $(dpkg -l | grep -i apparmor ) ]] ; then
        if [[ $( systemctl is-active apparmor.service ) == active ]] ; then
            echo Pass |tee -a $filename
            echo 'Note: Pam_Apparmor must have properly configured profiles. All configurations will be based on the actual system setup and organization. See the "Pam_Apparmor" documentation for more information on configuring profiles.' |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100867=3
        fi
    else
        echo Fail |tee -a $filename
        v100867=1
    fi

#V100869
    echo V-100869 |tee -a $filename
    if [[ -n $(dpkg -l | grep -i apparmor ) ]] ; then
        if [[ $( systemctl is-active apparmor.service ) == active ]] ; then
            if [[ $(systemctl is-enabled apparmor.service) ]]; then
                echo Pass |tee -a $filename
                echo 'Note: Pam_Apparmor must have properly configured profiles. All configurations will be based on the actual system setup and organization. See the "Pam_Apparmor" documentation for more information on configuring profiles.' |tee -a $filename
            else
            echo Fail |tee -a $filename
            v100869=1
            fi
        else
            echo Fail |tee -a $filename
            v100869=1
        fi
    else
        echo Fail |tee -a $filename
        v100869=1
    fi

#V100871
    echo V-100871 |tee -a $filename
    armored=$(apparmor_status)
    echo "If the defined profiles do not match the organizational list of authorized software for this computer, this is a finding." |tee -a $filename
    echo $armored |tee -a $filename
    v100871=2
    unset armored

#V100873 
    echo V-100873 |tee -a $filename
    if [[ -z $( cat /etc/passwd | awk -F: '{print $3}' | sort -n | uniq -d ) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        for i in `cat /etc/passwd | awk -F: '{print $3}' | sort -n | uniq -d`
        do
            echo $i
            grep "x:$i" /etc/passwd | tee -a $filename
        done
        v100873=2
    fi

#V100875
    echo V-100875 |tee -a $filename
    days=$( grep "^\s*INACTIVE" /etc/default/useradd | awk -F= '{print $2}')
    if ( [[ '0' -lt $days ]] && [[ $days -le '35' ]] ) ; then
        echo Pass $days |tee -a $filename
    else
        echo Fail $days |tee -a $filename
        v100875=1
    fi
    unset days

#V100877
    echo V-100877 |tee -a $filename
    echo Manual Check for emergency accounts |tee -a $filename
    v100877=2

#V100879
    echo V-100879 |tee -a $filename
    if [[ $( grep -i "^\s*umask" /etc/login.defs | awk '{print $2}' ) == 077 ]] ; then 
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100879=1
    fi

#V100881
    echo V-100881 |tee -a $filename
    echo Manual Check for emergency accounts |tee -a $filename
    v100881=2

#V100883
    echo V-100883 |tee -a $filename
    if [[ $( sysctl net.ipv4.tcp_syncookies | awk -F'= ' '{print $2}' ) == 1 ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100883=1
    fi

#V100885
    echo V-100885 |tee -a $filename
    if [[ -n $( dpkg -l | grep chrony) ]] ; then
        if [[ -n $( grep -i "^\s*server" /etc/chrony/chrony.conf) ]] ; then
            if [[ $( grep maxpoll /etc/chrony/chrony.conf | grep -v ^\# | awk '{print $NF}' ) == 17 ]] ; then
                echo Pass |tee -a $filename
            else
                echo Fail |tee -a $filename
                v100885=1
            fi
        else
            echo Fail - no time servers available | tee -a $filename
            v100885=2
        fi
    else
        echo Fail - chrony is not installed |tee -a $filename
        v100885=1
    fi

#V100887
    echo V-100887 |tee -a $filename
    if [[ -n $( dpkg -l | grep chrony) ]] ; then
        if [[ $( grep makestep /etc/chrony/chrony.conf | awk '{print $2" "$3 }' ) == '1 -1' ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100887=1
        fi
    else
        echo Fail - chrony is not installed |tee -a $filename
        v100887=1
    fi

#V100889
    echo V-100889 |tee -a $filename
    if [[ $(timedatectl status | grep -i "time zone") =~ " UTC" ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100889=1
    fi

#V100891
    echo V-100891 |tee -a $filename
    echo Manual Check of the firewall configuration |tee -a $filename
    #The Ubuntu operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
    v100891=2

#V100893
    echo V-100893 |tee -a $filename
    if [[ $(systemctl is-active kdump.service) == inactive ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100893=1
    fi

#V100895
    echo V-100895 |tee -a $filename
    if [[ -n $( dpkg -l | grep aide) ]] ; then
        if [[ $( for a in $( egrep '(\/sbin\/(audit|au))' /etc/aide/aide.conf | awk '{print $2}') ; do if [[ $a == "p+i+n+u+g+s+b+acl+xattrs+sha512" ]] ; then echo pass ; else echo fail ; fi ; done ) =~ fail ]] ; then 
            echo Fail |tee -a $filename
            v100895=3
        else
            echo Pass |tee -a $filename
        fi
    else 
        echo Fail |tee -a $filename
        v100895=1
    fi
    unset a

#V100897
    echo V-100897 |tee -a $filename
    if [[ $( systemctl is-enabled ufw) == enabled ]] ; then
        if [[ $( systemctl is-active ufw) == active ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100897=3
        fi
    else 
        echo Fail |tee -a $filename
        v100897=1
    fi

#V100899
    echo V-100899 |tee -a $filename
    if [[ $( grep ^\s*SILENTREPORTS /etc/default/aide 2>/dev/null | awk -F= '{print $2}') == no ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100899=1
    fi

#V100901
    echo V-100901 |tee -a $filename
    echo Manual Check of the firewall configuration |tee -a $filename
    #The Ubuntu operating system must configure the uncomplicated firewall to rate-limit impacted network interfaces.
    v100901=2

#V100903
    echo V-100903 |tee -a $filename
    if [[ $( dmesg | grep -i "execute disable") =~ "NX (Execute Disable) protection: active" ]] ; then
        echo Pass |tee -a $filename
    else 
        if [[ -n $( grep flags /proc/cpuinfo | grep -w nx ) ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail  |tee -a $filename
            v100903=1
        fi
        echo Fail  |tee -a $filename
        v100903=1
    fi

#V100905
    echo V-100905 |tee -a $filename
    if [[ $( sysctl kernel.randomize_va_space | awk -F= '{print $2}') == ' 2' ]] ; then
        echo Pass |tee -a $filename
    else 
        if [[ $( cat /proc/sys/kernel/randomize_va_space) == 2 ]] ; then
            echo Pass |tee -a $filename
        else
            echo Fail |tee -a $filename
            v100905=1
        fi
        echo Fail |tee -a $filename
        v100905=1
    fi

#V100907
    echo V-100907 |tee -a $filename
    if [[ -n $(dpkg -l | grep aide) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100907=1
    fi

#V100909
    echo V-100909 |tee -a $filename
    if [[ (-n $( ls -al /etc/cron.daily/aide 2>/dev/null)) || (-n $( ls -al /etc/cron.weekly/aide 2>/dev/null)) || (-n $( ls -al /etc/cron.monthly/aide 2>/dev/null)) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100909=1
    fi

#V100911
    echo V-100911 |tee -a $filename
    if [[ $( systemctl status ufw.service | grep -i "active:") =~ inactive ]] ; then
        echo Fail |tee -a $filename
        v100911=1
    else
        echo Pass |tee -a $filename
    fi

#V100913
    echo V-100913 |tee -a $filename
    echo Manual Check - The Ubuntu operating system must disable all wireless network adapters. |tee -a $filename
    v100913=2

#v100915
    echo V-100915 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        read -d '"EOF"' value << EOF
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid=0 -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -F key=perm_mod
EOF
        if [[ -z $(diff <( echo "$(auditctl -l | grep ' removexattr' | grep perm_mod )") <(echo "$value") 2>/dev/null) ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100915=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100915=1
    fi
    unset value


#V100917
    echo V-100917 |tee -a $filename
    if [[ -e "/sbin/auditctl" ]] ; then
        if [[ $(auditctl -l | grep -w 'crontab' ) =~ "-a always,exit -S all -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1" ]] ; then
            echo Pass |tee -a $filename
        else 
            echo Fail |tee -a $filename
            v100917=1
        fi
    else
        echo Fail - auditctl is not installed |tee -a $filename
        v100917=1
    fi
    
#V100919
    echo V-100919 |tee -a $filename
    if [[ ( -n $( grep usb-storage /etc/modprobe.d/* | grep "/bin/true" )) && ( -n $( grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" )) ]] ; then
        echo Pass |tee -a $filename
    else
        echo Fail |tee -a $filename
        v100919=1
    fi

fixfilename=fixFile_`date +%Y%m%d%H%M%S`
for (( i=100519; i<=100919; i++ )) do 
    vuln=v$i ; result="${!vuln}" 
    if [[ -n $(echo $result) ]] ; then 
        echo v$i $result >> $fixfilename
    fi
    unset $vuln
done

echo Please review $filename and perform necessary manual review of results, modifying $fixfilename to leave only results for which automated modification is needed
unset filename result vuln fixfilename

