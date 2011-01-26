#!/bin/sh
#-- CONFIG - EDIT THESE PARAMETERS FOR YOUR SYSTEM ----------------------------#
# FILES
# sshd logfile
logfile="/tmp/syslog.log"
# the file where you would like to keep all the BAD IPs
iplist="/opt/var/log/ssh_bf_uniques"
# the email template file (inside the template you can use $to, $log and $IP)
template="/usr/local/sbin/ISPemail.template"
# EXECUTABLES (you can find the paths by using "which $executableName")
whois="/opt/bin/whois"
diff="/opt/bin/diff"
iptables="/usr/sbin/iptables"
sendmail="/opt/sbin/sendmail"
#-- DO NOT MODIFY THE SCRIPT BELOW THIS LINE ----------------------------------#

################################################################################
# createEmailMessage() - parses the whois info for an IP and then composes an  #
# email message with the help of found information and a message template      #
#                                                                              #
# @param IP - the IP address for which the function should compose the message #
# @returns  - the exit code (0 for OK, 1 for error/warning)                    #
################################################################################
createEmailMessage() {
	to=""
	IP=$1
	if [[ -z "$IP" ]]; then
		echo "No IP given."
			return 1
	fi
	# search for the abuse email
	emails=`$whois $IP | grep abuse-mailbox | awk '{print $2}' | sort -u`

	# if emails is null search for any e-mail field
	if [[ -z "$emails" ]]; then
		emails=`$whois $IP | grep e-mail | awk '{print $2}' | sort -u`
	fi
	# if emails is still null then parse the whole whois info for an email
	if [[ -z "$emails" ]]; then
		emails=`$whois $IP | grep -E -o -i "\b[A-Z0-9._%+-~]+@[A-Z0-9.-]+\.[A-Z]{2,4}\b" | sort -u`
	fi
	if [[ -n "$emails" ]]; then
		for e in $emails; do
			to="$to $e"
		done
	else
		echo "WARNING: No email found in whois info"
		return 1
	fi
	# remove trailing whitespace
	to="${to##+([[:space:]])}"
	# replace all spaces left with commas
	to=`echo $to | sed 's/ /,/g'`
	log=`cat $logfile | grep $IP`
	eval "echo \"$(cat $template)\"" > message
	return 0
}

touch $iplist
 GET ALL ATTACKS
cat $logfile | grep sshd | grep "Invalid user" | awk 'BEGIN { FS=":" } ; {print $4}' | awk '{print $5}' > all
# SORT THEM
cat all | sort -u -n > uniques
# ADD ALREADY KNOWN
cat $iplist >> uniques
# MERGE THE LISTS
cat uniques | sort -u -n > new_uniques
# BLOCK THE NEW ONES
BLOCKDB=`$diff $iplist new_uniques | grep ">" | awk '{print $2}'`
if [ -n "$BLOCKDB" ] ; then
	echo "SSH log scanner `date`"
		for i in $BLOCKDB; do
			echo "Blocking $i"
			$iptables -A INPUT -s $i -j DROP

			# try to contact ISP
			createEmailMessage $i
			if [[ 0 -eq $? ]]; then
				$sendmail -t < message
				if [[ 0 -ne $? ]]; then
					echo "WARNING: Unable to send email"
				fi
				rm message
			fi 
        done
        # SAVE THE NEW LIST
        cat new_uniques > $iplist
fi
# CLEAN
rm uniques
rm all
rm new_uniques
