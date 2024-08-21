#!/usr/bin/env bash

# IP blacklisting script for Linux servers
# Pawel Krawczyk 2014-2015
# documentation https://github.com/kravietz/blacklist-scripts

# iptables logging limit
LIMIT="10/minute"

blocklist_chain_name=blocklists

link_set () {
    if [ "$3" = "log" ]; then
        iptables -A "$1" -m set --match-set "$2" src,dst -m limit --limit "$LIMIT" -j LOG --log-prefix "BLOCK $2 "
    fi
    iptables -A "$1" -m set --match-set "$2" src -j DROP
    iptables -A "$1" -m set --match-set "$2" dst -j DROP
}

# A firewall blacklist composed from IP lists, providing  maximum protection with minimum false positives. Suitable
# for basic protection on all internet facing servers,  routers and firewalls. (includes: bambenek_c2 dshield feodo
# fullbogons spamhaus_drop spamhaus_edrop sslbl ransomware_rw)
URLS="https://iplists.firehol.org/files/firehol_level1.netset"

# An ipset made from blocklists that track attacks, during  about the last 48 hours.
# (includes: blocklist_de dshield_1d greensnow)
URLS="$URLS https://iplists.firehol.org/files/firehol_level2.netset"

#     iblocklist.com is also supported
#     URLS="$URLS http://list.iblocklist.com/?list=srzondksmjuwsvmgdbhi&fileformat=p2p&archiveformat=gz&username=USERNAMEx$&pin=PIN"

# This is how it will look like on the server

# Chain blocklists (2 references)
#  pkts bytes target     prot opt in     out     source               destination
#     0     0 LOG        all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set manual-blacklist src,dst limit: avg 10/min burst 5 LOG flags 0 level 4 prefix "BLOCK manual-blacklist "
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set manual-blacklist src,dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set rules.emergingthreats src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set rules.emergingthreats dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.blocklist.de src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.blocklist.de dst
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.badips.com src
#     0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set www.badips.com dst

# check if we are on OpenWRT
if [ "$(which uci 2>/dev/null)" ]; then
    # we're on OpenWRT
    wan_iface=pppoe-wan
    IN_OPT="-i $wan_iface"
    INPUT=input_rule
    COMPRESS_OPT=""
else
    COMPRESS_OPT="--compressed"
    INPUT=INPUT
fi

# create main blocklists chain
if ! iptables -nL | grep -q "Chain ${blocklist_chain_name}"; then
    iptables -N ${blocklist_chain_name}
fi

# inject references to blocklist in the beginning of input and forward chains
if ! iptables -nL ${INPUT} | grep -q ${blocklist_chain_name}; then
  iptables -I ${INPUT} 4 ${IN_OPT} -j ${blocklist_chain_name}
fi

# flush the chain referencing blacklists, they will be restored in a second
iptables -F ${blocklist_chain_name}

# create the "manual" blacklist set
# this can be populated manually using ipset command:
# ipset add manual-blacklist a.b.c.d
set_name="manual-blacklist"
if ! ipset list | grep -q "Name: ${set_name}"; then
    ipset create "${set_name}" hash:net
fi
link_set "${blocklist_chain_name}" "${set_name}" "$1"

# download and process the dynamic blacklists
for url in $URLS
do
    # initialize temp files
    unsorted_blocklist=$(mktemp)
    sorted_blocklist=$(mktemp)
    new_set_file=$(mktemp)
    headers=$(mktemp)

    # download the blocklist
    set_name=$(echo "$url" | awk -F/ '{print substr($5,0,21);}') # set name is derived from source URL filename
    curl -L -v -s ${COMPRESS_OPT} -k "$url" >"${unsorted_blocklist}" 2>"${headers}"

    # this is required for blocklist.de that sends compressed content regardless of asked or not
    if [ -z "$COMPRESS_OPT" ]; then
        if grep -qi 'content-encoding: gzip' "${headers}"; then
            mv "${unsorted_blocklist}" "${unsorted_blocklist}.gz"
            gzip -d "${unsorted_blocklist}.gz"
        fi
    fi
    # autodetect iblocklist.com format as it needs additional conversion
    if echo "${url}" | grep -q 'iblocklist.com'; then
        if [ -f /etc/ipset-blacklist/range2cidr.awk ]; then
            mv "${unsorted_blocklist}" "${unsorted_blocklist}.gz"
            gzip -d "${unsorted_blocklist}.gz"
            awk_tmp=$(mktemp)
            awk -f /etc/ipset-blacklist/range2cidr.awk <"${unsorted_blocklist}" >"${awk_tmp}"
            mv "${awk_tmp}" "${unsorted_blocklist}"
        else
            echo "/etc/ipset-blacklist/range2cidr.awk script not found, cannot process ${unsorted_blocklist}, skipping"
            continue
        fi
    fi

    sort -u <"${unsorted_blocklist}" | egrep "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$" >"${sorted_blocklist}"

    # calculate performance parameters for the new set
    if [ "${RANDOM}" ]; then
        # bash
        tmp_set_name="tmp_${RANDOM}"
    else
        # non-bash
        tmp_set_name="tmp_$$"
    fi
    new_list_size=$(wc -l "${sorted_blocklist}" | awk '{print $1;}' )
    hash_size=$(expr $new_list_size / 2)

    if ! ipset -q list ${set_name} >/dev/null ; then
        ipset create ${set_name} hash:net family inet
    fi

    # start writing new set file
    echo "create ${tmp_set_name} hash:net family inet hashsize ${hash_size} maxelem ${new_list_size}" >>"${new_set_file}"

    # convert list of IPs to ipset statements
    while read line; do
        echo "add ${tmp_set_name} ${line}" >>"${new_set_file}"
    done <"$sorted_blocklist"

    # replace old set with the new, temp one - this guarantees an atomic update
    echo "swap ${tmp_set_name} ${set_name}" >>"${new_set_file}"

    # clear old set (now under temp name)
    echo "destroy ${tmp_set_name}" >>"${new_set_file}"

    # actually execute the set update
    ipset -! -q restore < "${new_set_file}"

    link_set "${blocklist_chain_name}" "${set_name}" "$1"

    # clean up temp files
    rm "${unsorted_blocklist}" "${sorted_blocklist}" "${new_set_file}" "${headers}"
done
