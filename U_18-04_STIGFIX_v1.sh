#!/bin/bash

    #########################################################
    #This Script will attempt to automate the implementation of the Ubuntu 18.04 STIG v1r2. 
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
    #for (( i=100519; i<=100919; i++ )) do
    #      if (( $i%2!=0 )) ; then  
    #        echo function v$i {| tee -a U_18-04_STIGFIX_v1.sh
    #        echo | tee -a U_18-04_STIGFIX_v1.sh
    #        echo } | tee -a U_18-04_STIGFIX_v1.sh
    #    fi
    #done

#Exit if no FIxFile is given.  Nothing to do.
if [[ -z $1 ]] ; then
    echo You must use a FixFile with this script
    exit
fi

#Create file to store script results
remFile=remediationResults_`date +%Y%m%d%H%M%S`

#Clean up any outstanding removals to avoid hearing aobut it every time we install things.
apt autoremove -y

#Establishing functions for correcting each STIG issue

function v100519 {
    #Once password on GRUB is in place, changing CLASS in /etc/grub.d/10_Linux 
    # to add "--unrestricted" will allow regular boot to work.
    #This has been added to avoid problems with rebooting after STIG application.    read -p 'Please enter the new grub username: ' grubuser
    read -p 'Please enter the new grub username: ' grubuser
    echo
    echo Please enter the new password for the grub user followed by pressing ENTER then do it again.
    hash=$(grub-mkpasswd-pbkdf2 | grep pbkdf2 | awk '{print $NF}' )
    sed -i '$ a set superusers=\"'$grubuser'\"\npassword_pbkdf2 '$grubuser' '$hash'' /etc/grub.d/40_custom
    [[ -n $(grep ^CLASS /etc/grub.d/10_linux | grep unrestricted) ]] || sed -i -E "/^CLASS/ s/\"$/ --unrestricted\"/" /etc/grub.d/10_linux
    #update grub
    echo Complete | tee -a $remFile
}
function v100521 {
    read -p 'Please enter the new grub username: ' grubuser
    echo
    echo Please enter the new password for the grub user followed by pressing ENTER then do it again.
    hash=$(grub-mkpasswd-pbkdf2 | grep pbkdf2 | awk '{print $NF}' )
    sed -i '$ a set superusers=\"'$grubuser'\"\npassword_pbkdf2 '$grubuser' '$hash'' /etc/grub.d/40_custom
    [[ -n $(grep ^CLASS /etc/grub.d/10_linux | grep unrestricted) ]] || sed -i -E "/^CLASS/ s/\"$/ --unrestricted\"/" /etc/grub.d/10_linux
    #update grub
    echo Complete | tee -a $remFile
}
function v100523 {
    if [[ -z $( grep GRUB_CMDLINE_LINUX /etc/default/grub | grep "audit=1" ) ]] ; then
        sed -i '/^\s*GRUB_CMDLINE_LINUX=/s/\"$/audit=1\"/' /etc/default/grub
    fi
    #update grub
    echo Complete | tee -a $remFile
}
function v100525 {
    echo Encrypting a partition in an already-installed system is more difficult because the existing partitions must be resized and changed. | tee -a $remFile
}
function v100527 {
    echo A subscription to the "Ubuntu Advantage" plan is required in order to obtain the FIPS Kernel cryptographic modules and enable FIPS.  | tee -a $remFile
    echo http://manpages.ubuntu.com/manpages/bionic/man1/ubuntu-advantage.1.html  | tee -a $remFile
}
function v100529 {
    if (( $1 == 1 )) ; then
        if [[ -z $( dpkg -l | grep auditd) ]] ; then
            apt install auditd -y
        fi
    fi
    action=$( grep "^\s*space_left_action" /etc/audit/auditd.conf | awk '{print $3}')
    limit=$( grep "^\s*space_left " /etc/audit/auditd.conf | awk '{print $3}')
    if ( [[ "$action" =~ [Ee][Mm][Aa][Ii][Ll] ]] ) ; then
        account=$( grep "^\s*action_mail_acct" /etc/audit/auditd.conf | awk '{print $3}')
        echo Manual Check Required - Space_left_action will email ${account} | tee -a $remFile
    else if [[ "$action" == *exec* ]] ; then
        echo Manual Check Required - Please make sure that ${action} notifies the System Administrator. | tee -a $remFile
        else 
            sed -i -E "/^space_left_action/ s/${action}/EMAIL/" /etc/audit/auditd.conf
            account=$( grep "^\s*action_mail_acct" /etc/audit/auditd.conf | awk '{print $3}')
            if [[ -z "$account" ]]; then
                sed -i -e '/action_email_acct =/ s/\$/root/' /etc/audit/auditd.conf
            fi
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
            sed -i -E "/^\s*space_left/ s/$limit/$pct/" /etc/audit/auditd.conf 
        fi
    fi
    echo Check results from scan and verify 'email' or 'exec' are set appropriately.  | tee -a $remFile
}
function v100531 {
    if (( $1 == 1 )) ; then
        apt install audispd-plugins -y
        sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf
        echo Do you have a remote server address/name for Audit log sending?
        while true; do
            read -p "(y/n)?" yn
            case $yn in
                [Yy]* ) read -p 'Enter server to receive remote audit logs: ' server ; sed -i -r "/remote_server/  s/$/ $server /" /etc/audisp/audisp-remote.conf ; echo Complete - remote server is $server | tee -a $remFile ; break ;;
                [Nn]* ) echo INCOMPLETE - You must fix this issue before v100531 is compliant. | tee -a $remFile ; break;;
                    * ) echo "Please answer yes or no.";;
            esac
        done
        systemctl restart auditd.service
    else 
        if (( $1 == 3 )) ; then
            sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf
            echo Do you have a remote server address/name for Audit log sending?
            while true; do
                read -p "(y/n)?" yn
                case $yn in
                    [Yy]* ) read -p 'Enter server to receive remote audit logs: ' server ; sed -i -r "/remote_server/  s/$/ $server /" /etc/audisp/audisp-remote.conf ; echo Complete - remote server is $server | tee -a $remFile ; break ;;
                    [Nn]* ) echo INCOMPLETE - You must fix this issue before v100531 is compliant. | tee -a $remFile ; break;;
                        * ) echo "Please answer yes or no.";;
                esac
            done
            systemctl restart auditd.service
        fi
    fi
}
function v100533 {
    if (( $1 == 3 )) ; then
        echo audit-offload cron job exists - please verify that it actually offloads data to a proper server.
        cat /etc/cron.weekly/audit-offload
        echo Does the above script offload audit logs to an approved server?
        while true; do
            read -p "(y/n)?" yn
            case $yn in
                [Yy]* ) echo Complete | tee -a $remFile ; break ;;
                [Nn]* ) echo Please fix /etc/cron.weekly/audit-offload to send audit logs to an approved server.  | tee -a $remFile ; break;;
                    * ) echo "Please answer yes or no.";;
            esac
        done
    else 
        if (( $1 == 2 )) ; then
            echo Completion of v100533 requires manual creation of /etc/cron.weekly/audit-offload which will offload audit logs to an approved server. | tee -a $remFile
        fi
    fi
}
function v100535 {
    for i in $(grep "^AllowUnauthenticated" /etc/apt/apt.conf.d/* | grep -vi "false" | awk -F: '{print $1}' ) 
    do 
        sed -i -E '/AllowUnauthenticated/ s/true/false/g' $i
    done
    echo Complete | tee -a $remFile
}
function v100537 {
    sed -i -e '/remove-unused-kernel-packages/I  s/false/true/i' -e '/remove-unused-kernel-packages/I  s/\/\///' -e '/remove-unused-dependencies/I  s/false/true/i' -e '/remove-unused-dependencies/I  s/\/\///' /etc/apt/apt.conf.d/50unattended-upgrades
    echo Complete | tee -a $remFile
}
function v100539 {
    apt-get autoremove nis -y
    echo Complete | tee -a $remFile
}
function v100541 {
    apt-get autoremove rsh-server -y
    echo Complete | tee -a $remFile
}
function v100545 {
    echo The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention \(ENSLTP\).  | tee -a $remFile
}
function v100547 {
    apt-get install rsyslog -y
    systemctl enable rsyslog
    systemctl restart rsyslog
    echo Complete | tee -a $remFile
}
function v100549 {
    apt-get install ufw -y
    echo Complete | tee -a $remFile
}
function v100551 {
    if (( $1 == 1 )) ; then
        apt install audispd-plugins -y
        sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf
        echo Do you have a remote server address/name for Audit log sending?
        while true; do
            read -p "(y/n)?" yn
            case $yn in
                [Yy]* ) read -p 'Enter server to receive remote audit logs: ' server ; sed -i -r "/remote_server/  s/$/ $server /" /etc/audisp/audisp-remote.conf ; echo Complete - remote server is $server | tee -a $remFile ; break ;;
                [Nn]* ) echo INCOMPLETE - You must fix this issue before v100531 is compliant. | tee -a $remFile ; break;;
                    * ) echo "Please answer yes or no.";;
            esac
        done
        systemctl restart auditd.service
    else 
        if (( $1 == 3 )) ; then
            sed -i -E 's/active\s*=\s*no/active = yes/' /etc/audisp/plugins.d/au-remote.conf
            echo Do you have a remote server address/name for Audit log sending?
            while true; do
                read -p "(y/n)?" yn
                case $yn in
                    [Yy]* ) read -p 'Enter server to receive remote audit logs: ' server ; sed -i -r "/remote_server/  s/$/ $server /" /etc/audisp/audisp-remote.conf ; echo Complete - remote server is $server | tee -a $remFile ; break ;;
                    [Nn]* ) echo INCOMPLETE - You must fix this issue before v100531 is compliant. | tee -a $remFile ; break;;
                        * ) echo "Please answer yes or no.";;
                esac
            done
            systemctl restart auditd.service
        fi
    fi
    echo Complete | tee -a $remFile
}
function v100553 {
    for i in $(grep offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf *.txt 2>/dev/null| awk -F: '{print $1}' )
    do
        sed -i -e '/offline_credentials_expiration/ s/=.*/= 1/' $i
    done
}
function v100555 {
    if [[ -z $(dpkg -l | grep libpam-pwquality ) ]] ; then
        apt install libpam-pwquality -y
    fi
    if (( $1 == 1 )) ; then
        sed -i -e '$ a auth required pam_faildelay.so delay = 4000000' /etc/pam.d/common-auth
    else 
        if (( $1 == 3 )) ; then
            if [[ $( grep pam_faildelay /etc/pam.d/common-auth ) =~ ^'auth required pam_faildelay.so delay=' ]] ; then
                a=$(grep pam_faildelay /etc/pam.d/common-auth | awk -F= '{print $2}' )
                sed -i -E "/pam_faildelay.so/ s/${a}/ 4000000/" /etc/pam.d/common-auth
            fi
        fi
    fi 
    echo Complete | tee -a $remFile
}
function v100557 {
    if [[ -n $(grep pam_lastlog /etc/pam.d/login) ]] ; then
        sed -i -e '/pam_lastlog.so/ s/^/\#/' /etc/pam.d/login
    fi
    sed -i -e '$ a \\n\#STIG v100557 \nsession required pam_lastlog.so showfailed' /etc/pam.d/login
    echo Complete | tee -a $remFile
}
function v100559 {
    if (( $1 == 3 )) ; then
        sed -i -e '/pam_tally2.so/  s/^/\#/' /etc/pam.d/common-auth
    fi
    sed -i -e '0,/^auth.*/s/^auth.*/auth required pam_tally2.so onerr=fail deny=3\n&/' /etc/pam.d/common-auth
    echo Complete | tee -a $remFile
}
function v100561 {
    if (( $1 == 2 )) ; then 
        #sed -i -e '/banner-message-text/,+12d ' /etc/gdm3/greeter.dconf-defaults
        echo Not complete | tee -a $remFile
        Please edit /etc/gdm3/greeter.dconf-defaults and remove entire entry for banner-message-text:w| tee -a $remFile
        grep -a 5 banner-message-text /etc/gdm3/greeter.dconf-defaults| tee -a $remFile
    else
        sed -i -e '$ a banner-message-text="You are accessing a U.S. Government \(USG\) Information System \(IS\) that is provided for USG-authorized use only.\n\nBy using this IS \(which includes any device attached to this IS\), you consent to the following conditions:\n\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct \(PM\), law enforcement \(LE\), and counterintelligence \(CI\) investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n\n-This IS includes security measures \(e.g., authentication and access controls\) to protect USG interests--not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." ' /etc/gdm3/greeter.dconf-defaults
        echo Complete | tee -a $remFile
    fi
}
function v100563 {
    passwd -l root
    echo Complete | tee -a $remFile
}
function v100565 {
    members=$(grep sudo /etc/group)
    echo Manual Check - Verify that the sudo group has only members who should have access to security functions.  |tee -a $remFile
    echo $members |tee -a $remFile
    unset members
}
function v100567 {
        read -d '"EOF"' bannerText << EOF
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.
EOF
    if ! [[ $( grep -i "^\s*banner" /etc/ssh/sshd_config | awk '{print $2}') == '/etc/issue' ]] ; then 
        sed -i -e '/Banner/ a Banner /etc/issue' -e '/#Banner/ d' /etc/ssh/sshd_config
    fi
    echo "$bannerText" > /etc/issue
    echo Complete | tee -a $remFile
}
function v100569 {
    if ! [[ $(grep 'pam_tally2.so' /etc/pam.d/common-auth) == "auth required pam_tally2.so onerr=fail deny=3" ]] ; then 
        sed -i -e '/pam_tally2.so/  s/^/\#/' /etc/pam.d/common-auth
        sed -i -e '0,/^auth.*/s/^auth.*/auth required pam_tally2.so onerr=fail deny=3\n&/' /etc/pam.d/common-auth
    else
        echo Fixed by previous error | tee -a $remFile
    fi
    echo Complete | tee -a $remFile
}
function v100571 {
    c=$(grep -i "^ucredit" /etc/security/pwquality.conf | awk -F= '{print $2}' )
    if [[ $c ]] ; then 
        sed -i -E "/ucredit/ s/${c}/ -1/" /etc/security/pwquality.conf
    else
        echo "ucredit=-1" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100573 {
    c=$(grep -i "^lcredit" /etc/security/pwquality.conf | awk -F= '{print $2}' )
    if [[ $c ]] ; then 
        sed -i -E "/lcredit/ s/${c}/ -1/" /etc/security/pwquality.conf
    else
        echo "lcredit=-1" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100575 {
    c=$(grep -i "^dcredit" /etc/security/pwquality.conf | awk -F= '{print $2}' )
    if [[ $c ]] ; then 
        sed -i -E "/dcredit/ s/${c}/ -1/" /etc/security/pwquality.conf
    else
        echo "dcredit=-1" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100577 {
    c=$(grep -i "^difok" /etc/security/pwquality.conf | awk -F= '{print $2}' )
    if [[ $c ]] ; then 
        sed -i -E "/difok/ s/${c}/ 8/" /etc/security/pwquality.conf
    else
        echo "difok = 8" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100579 {
    echo Manual Check - Current encryption method is "$( grep -i ^encrypt_method /etc/login.defs | awk '{print $2}' )" - Verify this is greater than SHA512  |tee -a $remFile
    echo Complete | tee -a $remFile
}
function v100581 {
    apt-get autoremove telnetd -y
    echo Complete | tee -a $remFile
}
function v100583 {
    c=$( grep -i ^pass_min_days /etc/login.defs | awk '{print $2}' )
    sed -i -E "/pass_min_days/I s/${c}/1/" /etc/login.defs
    unset c
    echo Complete | tee -a $remFile
}
function v100585 {
    c=$( grep -i ^pass_max_days /etc/login.defs | awk '{print $2}' )
    sed -i -E "/pass_max_days/I s/${c}/60/" /etc/login.defs
    unset c
    echo Complete | tee -a $remFile
}
function v100587 {
    if (( $1 == 1 )) ; then
        # comment current pam_unix line then insert new line above commented line
        sed -i -e '/pam_unix.so/ s/^/#/' -e '/pam_unix.so/ s/^#/password [success=1 default=ignore] pam_unix.so sha512 shadow remember=5 rounds=5000\n&/' /etc/pam.d/common-password
    else
        #change remember count to 5
        sed -i -e '/pam.unix.so/ s/remember=.* /remember=5 /' /etc/pam.d/common-password
    fi
    echo Complete | tee -a $remFile
}
function v100589 {
    c=$( grep -i ^minlen /etc/security/pwquality.conf | awk -F= '{print $2}' )
    if [[ $c ]] ; then 
        sed -i -E "/minlen/ s/${c}/ 15/" /etc/security/pwquality.conf
    else
        echo "minlen = 15" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100591 {
    echo Manual Check - Current encryption method is "$( grep -i ^encrypt_method /etc/login.defs | awk '{print $2}' )" - Verify this is greater than SHA512  |tee -a $remFile
    echo Manual Check - Verify the ecnryption method used here is greater than SHA512:  "$(  grep -i pam_unix.so /etc/pam.d/common-password  )" |tee -a $remFile
    echo Complete | tee -a $remFile
}
function v100593 {
    echo A policy must exist that ensures when a user account is created, it is created using a method that forces a user to change their password upon their next login. |tee -a $filename
    echo Potential methods to force a user to change their password include "chage -d 0 [UserName]" or "passwd -e [UserName]" |tee -a $filename
}
function v100595 {
    c=$( grep -i ^dictcheck /etc/security/pwquality.conf | awk -F= '{print $2}')
    if [[ -n $c ]] ; then 
        sed -i -E "/dictcheck/ s/${c}/ 1/" /etc/security/pwquality.conf
    else
        echo "dictcheck = 1" >> /etc/security/pwquality.conf
    fi
    unset c
    echo Complete | tee -a $remFile
}
function v100597 {
    sed -i -e '/\(nopasswd\|\!authenticate\)/I s/^/\#/' /etc/sudoers /etc/sudoers.d/*
}
function v100599 {
    function a {
        apt install libpam-pwquality -y
    }
    function b {
        if [[ $( grep -i ^enforcing /etc/security/pwquality.conf) ]] ; then
            c=$( grep -i ^enforcing /etc/security/pwquality.conf | awk -F' = ' '{print $2}') 
            sed -i -E "/enforcing/ s/$c/1/"
        else
            echo 'enforcing = 1' >> /etc/security/pwquality.conf
        fi
    }
    function c {
        if ! [[ $( grep pam.pwquality.so /etc/pam.d/common-password | awk  -F'[=\t ]' '{ for(i=1;i<=NF;i++) if ($i == "retry") print $(i+1) }' ) == [123] ]] ; then
            if [[ $( grep pam.pwquality.so /etc/pam.d/common-password) ]] ; then
                sed -i -e '/pam_pwquality.so/ s/^/#/' -e '/pam_pwquality.so/ s/^#/password requisite pam_pwquality.so retry=3\n&/' /etc/pam.d/common-password
            else
                sed -i -e '$ a  password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
            fi
        fi
    }
    if (( $1 == 1 )) ; then
        a
        b
        c
    else
        if (( $1 == 4 )) ; then
            b
            c
        else 
            if (( $1 == 3 )) ; then
                c
            fi
        fi
    fi
    echo Complete | tee -a $remFile
    unset c
}
function v100601 {
    find / -type d -perm -002 F875
    ! -perm -1000 -exec chmod +t {} \;
    echo Complete | tee -a $remFile
}
function v100603 {
    if [[ -f /etc/tmpfiles.d/stig.conf ]] ; then #if it's the first run don't add all the files to the tmpfiles configuration.
        for i in $( find /var/log -perm /137 -type f -exec stat -c "%n" {} \; ) 
        do  
            p=0$(stat -c "%a" $i)
            f=$( grep $i /usr/lib/tmpfiles.d/* /etc/tmpfiles.d/* | awk -F: '{print $1}' )
            if [[ -n $f ]] ; then 
                sed -i -e "/${i##*/}/ s/$p/0640/" $f
            else 
                [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
                sed -i -e "$ a z $i 0640 root utmp -" /etc/tmpfiles.d/stig.conf
            fi
        done
    fi 
    find /var/log -perm /137 -type f -exec chmod 640 {} \;
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100605 {
    i=/var/log 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $5}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/syslog/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root syslog -" /etc/tmpfiles.d/stig.conf
    fi
    chgrp syslog /var/log
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100607 {
    i=/var/log 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $4}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/root/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root syslog -" /etc/tmpfiles.d/stig.conf
    fi
    chown root /var/log
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100609 {
    i=/var/log 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $3}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/0750/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root syslog -" /etc/tmpfiles.d/stig.conf
    fi
    chmod 0750 /var/log
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100611 {
    chgrp adm /var/log/syslog
    echo Complete | tee -a $remFile
}
function v100613 {
    chown syslog /var/log/syslog
    echo Complete | tee -a $remFile
}
function v100615 {
    chmod 0640 /var/log/syslog
    echo Complete | tee -a $remFile
}
function v100617 {
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if ! [[ $(stat -c "%a" $i 2>/dev/null ) == '755' ]]; then
                chmod 0755 $i
            fi
        fi
    done
    echo Complete | tee -a $remFile
    unset i
}
function v100619 {
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if ! [[ $(stat -c "%U" $i 2>/dev/null ) == 'root' ]]; then
                chown root $i
            fi
        fi
    done
    echo Complete | tee -a $remFile
    unset i
}
function v100621 {
    for i in /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd /sbin/augenrules
    do
        if [[ -e "$i" ]] ; then
            if ! [[ $(stat -c "%G" $i 2>/dev/null ) == 'root' ]]; then
                chown root $i
            fi
        fi
    done
    echo Complete | tee -a $remFile
    unset i
}
function v100623 {
    find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
    echo Complete | tee -a $remFile
}
function v100625 {
    find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
    echo Complete | tee -a $remFile
}
function v100627 {
    find /lib /usr/lib /lib64 ! -user root -type f -exec chown root '{}' \;
    echo Complete | tee -a $remFile
}
function v100629 {
    find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \;
    echo Complete | tee -a $remFile
}
function v100631 {
    find /lib /usr/lib /lib64 ! -group root -type f -exec chgrp root '{}' \;
    echo Complete | tee -a $remFile
}
function v100633 {
    find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \;
    echo Complete | tee -a $remFile
}
function v100635 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
    echo Complete | tee -a $remFile
}
function v100637 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \;
    echo Complete | tee -a $remFile
}
function v100639 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec chown root '{}' \;
    echo Complete | tee -a $remFile
}
function v100641 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \;
    echo Complete | tee -a $remFile
}
function v100643 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec chgrp root '{}' \;
    echo Complete | tee -a $remFile
}
function v100645 {
    find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' \;
    echo Complete | tee -a $remFile
}
function v100647 {
    if [[ $( grep -i ^ocredit /etc/security/pwquality.conf) ]] ; then
        c=$( grep -i ^ocredit /etc/security/pwquality.conf | awk -F' = ' '{print $2}') 
        sed -i -E "/ocredit/ s/$c/-1/"
    else
        echo 'ocredit = -1' >> /etc/security/pwquality.conf
    fi
    echo Complete | tee -a $remFile
    unset c
}
function v100649 {
    for f in $(grep logout /etc/dconf/db/local.d/* 2>/dev/null | awk -F: '{print $1}')
    do 
        if [[ -n $(grep logout $f | awk -F= '{print $2}') ]] ; then
            sed -i -E "/logout/ s/${c}/''/" $f 
        fi
    done
    echo Complete | tee -a $remFile
    unset f
}
function v100651 {
    systemctl mask ctrl-alt-del.target
    systemctl daemon-reload
    echo Complete | tee -a $remFile
}
function v100653 {
    echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100655 {
    echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100657 {
    echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100659 {
    echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100661 {
    echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100663 {
    echo "-w /var/run/wtmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100665 {
    echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100667 {
    echo "-w /etc/passwd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100669 {
    echo "-w /etc/group -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100671 {
    echo "-w /etc/gshadow -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100673 {
    echo "-w /etc/shadow -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100675 {
    echo "-w /etc/security/opasswd -p wa -k usergroup_modification" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100677 {
    if [[ -z $(dpkg -l | grep auditd) ]] ; then
        apt-get install auditd -y
    fi
    systemctl enable auditd.service
    echo Complete | tee -a $remFile
}
function v100679 {
    if (( $1 == 2 )) ; then
        account=$(grep "^\s*action_mail_acct" /etc/audit/auditd.conf | awk '{print $3}')
        echo Manual Check - Space_left_action will email ${account} |tee -a $remFile
    else
        if [[ $(grep action_mail_acct /etc/audit/auditd.conf) ]] ; then
            c=$(grep action_mail_acct /etc/audit/auditd.conf | awk -F' = ' '{print $2}')
            sed -i -E "/action_mail_acct/ s/^#//" -E "/action_mail_acct/ s/${c}/root/"
            echo Complete | tee -a $remFile
        else
            if [[ -e /etc/audit/auditd.conf ]] ; then
                echo action_mail_acct = root >> /etc/audit/auditd.conf
                echo Complete | tee -a $remFile
            else 
                echo Audit is not yet installed - install and configure |tee -a $remFile
            fi
        fi
    fi
    unset account
}
function v100681 {
    if (( $1 == 3 )) ; then
        action=$(grep disk_full_action /etc/audit/auditd.conf | awk '{print $3}')
        sed -i -E "/disk_full_action/ s/${action}/HALT/" /etc/audit/auditd.conf
    else
        if [[ -e /etc/audit/auditd.conf ]] ; then
            echo disk_full_action = HALT >> /etc/audit/auditd.conf
            echo Complete | tee -a $remFile
        else 
            echo Audit is not yet installed - install and configure |tee -a $remFile
        fi
    fi
    echo Complete | tee -a $remFile
}
function v100683 {
    i=$( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) 
    p=$( stat -c "%a" $i  )
    f=$( grep $i /etc/tmpfiles.d/* | awk -F: '{print $1}' )
    [[ -z $f ]] && f=$( grep $i /usr/lib/tmpfiles.d/* | awk -F: '{print $1}' )
    if [[ -n $f ]] ; then 
        sed -i -e "/${i##*/}/ s/.$p/0600/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        sed -i -e "$ a z $i 0600 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chmod 0600 $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' )
    echo Complete | tee -a $remFile
    unset i p f
}
function v100685 {
    i=$( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) 
    p=$( stat -c "%U" $i  )
    f=$( grep $i /etc/tmpfiles.d/* | awk -F: '{print $1}' )
    [[ -z $f ]] && f=$( grep $i /usr/lib/tmpfiles.d/* | awk -F: '{print $1}' )
    if [[ -n $f ]] ; then 
        sed -i -e "/${i##*/}/ s/$p/root/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        sed -i -e "$ a z $i 0600 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chown root $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' )
    echo Complete | tee -a $remFile
    unset i p f
}
function v100687 {
    i=$( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) 
    p=$( stat -c "%G" $i  )
    f=$( grep $i /etc/tmpfiles.d/* | awk -F: '{print $1}' )
    [[ -z $f ]] && f=$( grep $i /usr/lib/tmpfiles.d/* | awk -F: '{print $1}' )
    if [[ -n $f ]] ; then 
        sed -i -e "/${i##*/}/ s/$p/root/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        sed -i -e "$ a z $i 0600 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chown :root $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' )
    echo Complete | tee -a $remFile
    unset i p f
}
function v100689 {
    i=$(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $3}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/0750/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chmod -R g-w,o-rwx $(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' )) 
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100691 {
    i=$(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $4}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/root/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chown -R root $(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ))
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100693 {
    i=$(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ) ) 
    read f n <<< $( grep -n "$i " /etc/tmpfiles.d/* | awk -F: '{print $1" "$2}' )
    [[ -n $f ]] && p=$( grep "$i " $f | awk '{print $5}' )
    if [[ -n $f ]] && [[ -n $p ]] ; then 
        sed -i -e "$n s/$p/root/" $f
    else 
        [ ! -f /etc/tmpfiles.d/stig.conf ] && echo \#STIG settings >> /etc/tmpfiles.d/stig.conf && chmod 644 /etc/tmpfiles.d/stig.conf
        [[ -n $n ]] && sed -e "$n s/^/#/" 
        sed -i -e "$ a z $i 0750 root root -" /etc/tmpfiles.d/stig.conf
    fi
    chown -R :root $(dirname $( grep -iw log_file /etc/audit/auditd.conf 2>/dev/null | awk -F= '{print $2}' ))
    echo Complete | tee -a $remFile
    unset i p f n
}
function v100695 {
        chmod -R 0640 /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
        echo Complete | tee -a $remFile
}
function v100697 {
        chown root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
        echo Complete | tee -a $remFile
}
function v100699 {
        chown :root /etc/audit/audit*.{rules,conf} /etc/audit/rules.d/*
        echo Complete | tee -a $remFile
}
function v100701 {
    folder=$(dirname $(grep ^log_file /etc/audit/auditd.conf 2>/dev/null | awk -F' = ' '{print $2}' ) 2>/dev/null )
    mountPoint=$(df -h $folder | grep ^/dev/ | awk '{print $NF}' )
    partSize=$(df -h $folder | grep ^/dev/ | awk '{print $2}' )
    case $1 in
    1)
        echo Manual Check required - At time of check $folder did not exist.  Verify that it has been created.
        ;;
    2)
        echo Manual Fix required - Audit logs should be on a separate partition with at least 10G available |tee -a $remFile
        echo There may be insufficient space on $mountPoint for audit logs -- $partFree space available |tee -a $remFile
        ;;
    3)
        echo Manual Fix required - $mountPoint is $partSize and should be at least 10G |tee -a $remFile
        ;;
    esac
}
function v100703 {
    echo "-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100705 {
    echo "-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chfn" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100707 {
    echo "-a always,exit -F path=/bin/mount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100709 {
    echo "-a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-umount" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100711 {
    echo "-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100713 {
    echo "-a always,exit -F path=/usr/lib/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-ssh" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100715 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod 
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100717 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k perm_mod 
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod 
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100719 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100721 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100723 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100725 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S chown -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100727 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S fchown -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100729 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S fchownat -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100731 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100733 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S chmod -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100735 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S fchmod -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100737 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b64 -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100739 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100741 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100743 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100745 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100747 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100749 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100751 {
    echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100753 {
    echo "-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100755 {
    echo "-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100757 {
    echo "-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k priv_cmd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100759 {
    echo "-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100761 {
    echo "-a always,exit -F path=/sbin/apparmor_parser -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100763 {
    echo "-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100765 {
    echo "-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=4294967295 -k perm_chng" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100767 {
    echo "-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100769 {
    echo "-a always,exit -F path=/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-update" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100771 {
    echo "-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-gpasswd" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100773 {
    echo "-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-chage" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100775 {
    echo "-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-usermod" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100777 {
    echo "-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-pam_timestamp_check" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100779 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100781 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100783 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng
-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100785 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S execve -C uid!=euid -F key=execpriv 
-a always,exit -F arch=b64 -S execve -C gid!=egid -F key=execpriv 
-a always,exit -F arch=b32 -S execve -C uid!=euid -F key=execpriv 
-a always,exit -F arch=b32 -S execve -C gid!=egid -F key=execpriv
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100787 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100789 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100791 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100793 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100795 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_chng
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100797 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S unlink -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -F auid>=1000 -F auid!=4294967295 -k delete
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100799 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S unlinkat -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlinkat -F auid>=1000 -F auid!=4294967295 -k delete
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100801 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S rename -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k delete
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100803 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b64 -S renameat -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100805 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S init_module -S finit_module -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -k modules
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100807 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S delete_module -k modules
-a always,exit -F arch=b64 -S delete_module -k modules
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100809 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100811 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100813 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access
-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100815 {
    #    read -d '"EOF"' rules << EOF
    #-a always,exit -F arch=b32 -S init_module -S finit_module -F key=modules
    #-a always,exit -F arch=b64 -S init_module -S finit_module -F key=modules
    #EOF
    #    echo "$rules" >> /etc/audit/rules.d/stig.rules
    #    echo Complete | tee -a $remFile
    echo This rule creates a problem because it duplicates 100805
}
function v100817 {
    #    read -d '"EOF"' rules << EOF
    #-a always,exit -F arch=b32 -S delete_module -F key=modules
    #-a always,exit -F arch=b64 -S delete_module -F key=modules
    #EOF
    #    echo "$rules" >> /etc/audit/rules.d/stig.rules
    #    echo Complete | tee -a $remFile
    echo This rule creates a problem because it duplicates 100807
}
function v100819 {
    echo "-w /sbin/modprobe -p x -k modules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100821 {
    echo "-w /bin/kmod -p x -k modules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100823 {
    echo "-w /bin/fdisk -p x -k fdisk" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100825 {
    if (( $1 == 3 )) ; then
        c=$( grep '^* hard maxlogins' /etc/security/limits.conf | awk '{print $NF}' )
        sed -i -E "/hard maxlogins/ s/${c}/10/" /etc/security/limits.conf
    else
        sed -i -e '$ i * hard maxlogins 10\n' /etc/security/limits.conf
    fi
    echo Complete | tee -a $remFile
    unset c
}
function v100827 {
    gsettings set org.gnome.desktop.screensaver lock-enabled true
    echo Complete | tee -a $remFile
}
function v100829 {
    touch /etc/profile.d/autologout.sh
    read -d '"EOF"' value << EOF
TMOUT=900
readonly TMOUT
export TMOUT
EOF
    echo "$value" >> /etc/profile.d/autologout.sh
    unset TMOUT
    echo Complete | tee -a $remFile
}
function v100831 {
    apt-get install vlock -y
    echo Complete | tee -a $remFile
}
function v100833 {
    if [[ -z $(grep -i "^\s*clientalive" /etc/ssh/sshd_config) ]] ; then
        echo ClientAliveInterval 600 >> /etc/ssh/sshd_config
    else
        c=$( grep -i "^\s*clientalive" /etc/ssh/sshd_config | awk '{print $2}')
        sed -i -E "/clientalive/I s/${c}/600/" /etc/ssh/sshd_config
    fi
    echo Complete | tee -a $remFile
}
function v100835 {
    read -d '"EOF"' value << EOF
auth.*,authpriv.* /var/log/secure
daemon.notice /var/log/messages
EOF
    echo "$value" >> /etc/rsyslog.d/50-default.conf
    echo Complete | tee -a $remFile
}
function v100837 {
    if [[ -z $( grep -E '^\s*Ciphers ' /etc/ssh/sshd_config) ]] ; then
        echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
    else 
        sed -i -e '/ciphers/I s/^/#/' -e '/ciphers/I a Ciphers aes128-ctr,aes192-ctr,aes256-ctr' /etc/ssh/sshd_config
    fi
    echo Complete | tee -a $remFile
}
function v100839 {
    c=$(grep -i ^\s*Protocol /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*Protocol /etc/ssh/sshd_config && sed -i -e "/^Protocol/ s/${c}/2/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a Protocol 2" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100841 {
    c=$(grep -i ^\s*UsePAM /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*UsePam /etc/ssh/sshd_config && sed -i -e "/^UsePam/ s/${c}/yes/" /etc/ssh/sshd_config || (c='$' ; sed -i -e "${c} a UsePam yes" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100843 {
    c=$(grep -i ^\s*ClientAliveCountMax /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*ClientAliveCountMax /etc/ssh/sshd_config && sed -i -e "/^ClientAliveCountMax/ s/${c}/1/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a ClientAliveCountMax 1" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100845 {
    c=$(grep -i ^\s*ClientAliveInterval /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*ClientAliveInterval /etc/ssh/sshd_config && sed -i -e "/^ClientAliveInterval/ s/${c}/600/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a ClientAliveInterval 600" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100847 {
    c=$(grep -i ^\s*macs /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*MACs /etc/ssh/sshd_config && sed -i -e "/^MACs/ s/${c}/hmac-sha2-256,hmac-sha2-512/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a MACs hmac-sha2-256,hmac-sha2-512" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100849 {
    if (( $1 == 1 )) ; then
        apt install sshd -y
        systemctl enable sshd.service
        systemctl start sshd.service
    else
        systemctl enable sshd.service
        systemctl start sshd.service
    fi
    echo Complete | tee -a $remFile
}
function v100851 {
    c=$(grep -i ^\s*PermitEmptyPasswords /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*PermitEmptyPasswords /etc/ssh/sshd_config && sed -i -e "/^PermitEmptyPasswords/ s/${c}/no/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a PermitEmptyPasswords no" /etc/ssh/sshd_config )
    c=$(grep -i ^\s*PermitUserEnvironment /etc/ssh/sshd_config | awk '{print $2}')
    grep -i ^\s*PermitUserEnvironment /etc/ssh/sshd_config && sed -i -e "/^PermitUserEnvironment/ s/${c}/no/" /etc/ssh/sshd_config || ( c='$' ; sed -i -e "${c} a PermitUserEnvironment no" /etc/ssh/sshd_config )
    echo Complete | tee -a $remFile
}
function v100853 {
    echo Manual Fix Required - The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path \(which includes status information\) to an accepted trust anchor. | tee -a $remFile
}
function v100855 {
    echo Manual Fix Required - The Ubuntu operating system must map the authenticated identity to the user or group account for PKI-based authentication. | tee -a $remFile
}
function v100857 {
    echo Manual Fix Required - Configure the Ubuntu operating system to use smart card logins for multifactor authentication for local access to accounts. | tee -a $remFile
}
function v100859 {
    echo Manual Fix Required - The Ubuntu operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access. | tee -a $remFile
}
function v100861 {
    echo Manual Fix Required - The Ubuntu operating system must accept Personal Identity Verification \(PIV\) credentials. | tee -a $remFile
}
function v100863 {
    echo Manual Fix Required - The Ubuntu operating system must implement certificate status checking for multifactor authentication. | tee -a $remFile
}
function v100865 {
    echo Manual Fix Required - The Ubuntu operating system must only allow the use of DoD PKI-established certificate authorities for verification of the establishment of protected sessions. | tee -a $remFile
}
function v100867 {
    if (( $1 == 1 )) ; then
        apt-get install libpam-apparmor -y 
        systemctl enable apparmor.service
        systemctl start apparmor.service
    else
        systemctl enable apparmor.service
        systemctl start apparmor.service
    fi
    echo 'Note: Pam_Apparmor must have properly configured profiles. All configurations will be based on the actual system setup and organization. See the "Pam_Apparmor" documentation for more information on configuring profiles.' | tee -a $remFile
    echo Configure the Ubuntu operating system to allow system administrators to pass information to any other Ubuntu operating system administrator or user. | tee -a $remFile
}
function v100869 {
    if (( $1 == 1 )) ; then
        apt-get install libpam-apparmor -y 
        systemctl enable apparmor.service
        systemctl start apparmor.service
    else
        systemctl enable apparmor.service
        systemctl start apparmor.service
    fi
    echo 'Note: Apparmor must have properly configured profiles for applications and home directories. All configurations will be based on the actual system setup and organization and normally are on a per role basis. See the "Apparmor" documentation for more information on configuring profiles.' | tee -a $remFile
    echo The Ubuntu operating system must be configured to use AppArmor. | tee -a $remFile
}
function v100871 {
    if (( $1 == 1 )) ; then
        apt-get install libpam-apparmor -y 
        systemctl enable apparmor.service
        systemctl start apparmor.service
    else
        systemctl enable apparmor.service
        systemctl start apparmor.service
    fi
    echo 'Note: Apparmor must have properly configured profiles for applications and home directories. All configurations will be based on the actual system setup and organization and normally are on a per role basis. See the "Apparmor" documentation for more information on configuring profiles.' | tee -a $remFile
    echo The Apparmor module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders. | tee -a $remFile
}
function v100873 {
    if [[ -z $( cat /etc/passwd | awk -F: '{print $3}' | sort -n | uniq -d ) ]] ; then
        echo Manual Fix required - Edit the file "/etc/passwd" and provide each interactive user account that has a duplicate User ID \(UID\) with a unique UID. | tee -a $remFile
        echo The following accounts have a duplicate UID:  | tee -a $remFile
        for i in `cat /etc/passwd | awk -F: '{print $3}' | sort -n | uniq -d`
        do
            echo $i
            grep "x:$i" /etc/passwd | tee -a $remFile
        done
    fi
    }
function v100875 {
    c=$(grep -i INACTIVE /etc/default/useradd | awk -F= '{print $2}')
    if [[ -n $(grep -i ^\s*INACTIVE /etc/default/useradd) ]] ; then
        sed -i -e "/^INACTIVE/ s/${c}/35/" /etc/default/useradd 
    else
        if [[ -n $(grep -i INACTIVE /etc/default/useradd) ]] ; then 
            sed -i -e "/INACTIVE/I a INACTIVE=35" /etc/default/useradd
        else 
            c='$'
            sed -i -e "${c} a INACTIVE=35" /etc/default/useradd
        fi
    fi
    echo Complete | tee -a $remFile
}
function v100877 {
    echo Manually Check for emergency accounts | tee -a $remFile
    echo If an emergency account must be created, configure the system to terminate the account after a 72 hour time period with the following command to set an expiration date on it. Substitute "account_name" with the account to be created. | tee -a $remFile
    echo \t chage -E $(date -d "+3 days" +%F) account_name | tee -a $remFile
}
function v100879 {
    c=$( grep -i ^umask /etc/login.defs | awk '{print$2}' )
    [[ -n $(grep -i ^\s*UMASK /etc/login.defs) ]] && sed -i -e "/^UMASK/ s/${c}/077/" /etc/login.defs || ( c='$' ; sed -i -e "${c} a UMASK 077" /etc/login.defs )
    echo Complete | tee -a $remFile
}
function v100881 {
    echo Manual Check for temporary accounts | tee -a $remFile
    echo If a temporary account must be created configure the system to terminate the account after a 72 hour time period with the following command to set an expiration date on it. Substitute "system_account_name" with the account to be created. | tee -a $remFile
    echo sudo chage -E $(date -d "+3 days" +%F) system_account_name | tee -a $remFile
}
function v100883 {
    sysctl -w net.ipv4.tcp_syncookies=1
    c=$(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf)
    [[ -z $c ]] && c='$' || c="$c"
    sed -i -e "/${c}/ s/^/#/" -e "/${c}/a net.ipv4.tcp_syncookies = 1" /etc/sysctl.conf
    echo Complete | tee -a $remFile
}
function v100885 {
    if [[ -z $(dpkg -l | grep chrony) ]] ; then
        apt install chrony -y
    fi
    c=$( grep -i "^\s*server" /etc/chrony/chrony.conf)
    [[ -z $c ]] && echo Add servers to /etc/chrony/chrony.conf | tee -a $remFile || sed -i -e "/^\s*server/ s/maxpoll [0-9]*/maxpoll 17/" /etc/chrony/chrony.conf
    echo Complete | tee -a $remFile
}
function v100887 {
    c=$( grep -i "^\s*makestep" /etc/chrony/chrony.conf)
    [[ -z $c ]] && echo makestep 1 -1 >> /etc/chrony/chrony.conf || sed -i -e "/^\s*makestep/ s/makestep [0-9] .*[0-9]/makestep 1 -1/" /etc/chrony/chrony.conf
    echo Complete | tee -a $remFile
}
function v100889 {
    timedatectl set-timezone UTC
    echo Complete | tee -a $remFile
}
function v100891 {
    echo Manually configure ufw firewall | tee -a $remFile
}
function v100893 {
    systemctl disable kdump.service
    echo Complete | tee -a $remFile
}
function v100895 {
    read -d '"EOF"' value << EOF
/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512
/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
EOF
    if [[ -n $( dpkg -l | grep aide) ]] ; then
        apt install aide -y
        [[ -z $(grep '/sbin/au' /etc/aide/aide.conf) ]] && echo "$value" >> /etc/aide/aide.conf || sed -i -E "/\/sbin\/au/ s/ .*$/ p+i+n+u+g+s+b+acl+xattrs+sha512/" /etc/aide/aide.conf
    else
        [[ -z $(grep '/sbin/au' /etc/aide/aide.conf) ]] && echo "$value" >> /etc/aide/aide.conf || sed -i -E "/\/sbin\/au/ s/ .*$/ p+i+n+u+g+s+b+acl+xattrs+sha512/" /etc/aide/aide.conf
    fi
    echo Complete | tee -a $remFile
    unset value
}
function v100897 {
    if (( $1 == 1 )) ; then
        systemctl enable ufw.service 
    fi
        systemctl start ufw.service
    echo Complete | tee -a $remFile
}
function v100899 {
    [[ -n $( grep SILENTREPORTS /etc/default/aide) ]] && sed -i -e '/SILENTREPORTS/ s/^.*SI/SI/' -e '/SILENTREPORTS/ s/=.*/=no/' /etc/default/aide || sed -i -e "$ a SILENTREPORTS=no" /etc/default/aide
    echo Complete | tee -a $remFile
}
function v100901 {
    for i in $(ip -br link | awk '{print $1}' | grep -v lo)
    do  
        ufw limit in on $i
    done
    echo Complete | tee -a $remFile
}
function v100903 {
    echo Manual check - reboot server and check BIOS for XD/NX \(No eXecute\) protection | tee -a $remFile
}
function v100905 {
    sed -i -e '/kernel.randomize_va_space/d' /etc/sysctl.conf
    echo Complete | tee -a $remFile
}
function v100907 {
    if [[ -z $( dpkg -l | grep aide) ]] ; then
        apt install aide -y
    fi
    echo Complete | tee -a $remFile
}
function v100909 {
    cp /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide
    echo Complete | tee -a $remFile
}
function v100911 {
    systemctl enable ufw.service 
    systemctl start ufw.service
    echo Complete | tee -a $remFile
}
function v100913 {
    echo Manual Check - The Ubuntu operating system must disable all wireless network adapters. |tee -a $remFile
}
function v100915 {
    read -d '"EOF"' rules << EOF
-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod
EOF
    echo "$rules" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100917 {
    echo "-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-crontab" >> /etc/audit/rules.d/stig.rules
    echo Complete | tee -a $remFile
}
function v100919 {
    echo install usb-storage /bin/true >> /etc/modprobe.d/DISASTIG.conf
    echo blacklist usb-storage >> /etc/modprobe.d/DISASTIG.conf
    echo Complete | tee -a $remFile
}

fixFile=$1
#Search fixFile    
for (( z=100519; z<=100919; z++ )) do  
    if (( $z%2!=0 )) ; then  
        if [[ -n $(grep v$z $fixFile) ]] ; then
            if [[ $(grep v$z $fixFile | awk '{print $2}' ) == 2 ]] ; then
                echo v$z requires a manual check and correction. | tee -a $remFile
                v$z $(grep v$z $fixFile | awk '{print $2}' )
            else
                echo v$z | tee -a $remFile
                v$z $(grep v$z $fixFile | awk '{print $2}' )
            fi
        fi
    fi
done

update-grub
augenrules --load

echo This server requires a reboot to finish implementation of all settings.  | tee -a $remFile
echo Please be sure you will have access after the system reboots. | tee -a $remFile

    #For files which permissions do not seem to be staying changed look at 
    #    /etc/tmpfiles.d/*.conf
    #    /run/tmpfiles.d/*.conf
    #    /usr/lib/tmpfiles.d/*.conf
    #per https://unix.stackexchange.com/questions/377376/permissions-on-var-log-reset-on-boot
