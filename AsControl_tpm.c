////////////////////////////////////////////////////////////////////////////////
//
//  File          : AsControl.c
//  Description   : The AsControl module implements a shim for the system
//                  trust validation for the arpsec deamon
//
//  Author  : Patrick McDaniel
//  Created : Tue Mar 26 10:25:00 EDT 2013
//  Dev	    : daveti

//
// Includes
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

// Project Includes
#include "AsControl.h"
#include "AsLogic.h"
#include "AsKrnRelay.h"
#include "AsLog.h"
#include "AsTMeasure.h"
#include "AsNetlink.h"
#include "AsTpmDB.h"
#include "AsWhiteList.h"
#include "tpmw.h"
#include "timer_queue.h"
#include "timer_thread.h"
// Includes for PCAP
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <libnet.h>
#include <pcap.h>
#include <libnetlink.h>
#include "AsKrnProc.h"
#include "AsPcap.h"
#include "AsNet.h"
#include "AsNeighbor.h"
#include "AsTime.h"

// Defines
#define SELECT_WAIT_PERIOD 1

// Module data
int	ascControlDone = 0;
int	ascForceAttestFlag = 0;	    // daveti: Force the attestation even if the logic approves
int	ascEnableCacheFlag = 0;	    // daveti: Enable cache (using the whitelist) if the attestation succeeds
char	*ascLocalSystem = NULL;	    // The name of the local system (logic format)
char	*ascLocalNet = NULL;	    // The local network address name (logic format)
char	*ascLocalMedia = NULL;	    // The local media address name (logic format)
extern pthread_mutex_t	timer_queue_mutex;	// daveti: timer queue mutex
static pthread_t	timer_thread_tid;	// daveti: timer thread id

// Pcap globals
pcap_t *descr;
u_int32_t myIP;
libnet_t *l;
char *myMAC;

//
// Module functions

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascEnableCache
// Description  : Enable the cache (using the whitelist) if the attestation succeeds
//
// Inputs       : void
// Outputs      : void

void ascEnableCache(void)
{
        ascEnableCacheFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascForceAttest
// Description  : Force the attestation even if the logic approves - for UT!
//
// Inputs       : void
// Outputs      : void

void ascForceAttest(void)
{
	ascForceAttestFlag = 1;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascGetLocalNet
// Description  : Get the local infomation associated with this process
//
// Inputs       : void
// Outputs      : ascLocalNet

char *ascGetLocalNet(void)
{
    return ascLocalNet;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascGetLocalMedia
// Description  : Get the local infomation associated with this process
//
// Inputs       : void
// Outputs      : ascLocalMedia

char *ascGetLocalMedia(void)
{
    return ascLocalMedia;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalSystem
// Description  : Setup the local infomation associated with this process
//
// Inputs       : sys - the local system name
// Outputs      : 0 if successful, -1 if not

void ascSetLocalSystem( char *sys ) {
    // Set value and return
    ascLocalSystem = sys;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalNet
// Description  : Setup the local infomation associated with this process
//
// Inputs       : net - the local network address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalNet( char *net) {
    // Set value and return
    ascLocalNet = net;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascSetLocalMedia
// Description  : Setup the local infomation associated with this process
//
// Inputs       : med - the local media address
// Outputs      : 0 if successful, -1 if not

void ascSetLocalMedia(  char *med ) {
    // Set value and return
    ascLocalMedia = med;
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascDumpLocalInfo
// Description	: Dump the local information for debugging
//
// Inputs	: void
// Outputs	: void
// Dev		: daveti

void ascDumpLocalInfo(void)
{
	asLogMessage("Info - LocalSystem: %s", ascLocalSystem);
	asLogMessage("Info - LocalNet: %s", ascLocalNet);
	asLogMessage("Info - LocalMedia: %s", ascLocalMedia);
	return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascReleaseMemForLocalInfo
// Description  : Release the memory for local information
//
// Note		: This function only works for ASKRN_RELAY mode!
// Inputs       : void
// Outputs      : void
// Dev          : daveti

void ascReleaseMemForLocalInfo(void)
{
	// free the memory for setup local info
	if (ascLocalSystem)
		free(ascLocalSystem);
	if (ascLocalNet)
		free(ascLocalNet);
	if (ascLocalMedia)
		free(ascLocalMedia);

        return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingNetworkBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 1 if successful, 0 if failure
// Dev		: daveti

int ascPendingNetworkBinding( AsNetworkAddress addr ) {
    // For now, just return pending for everything
    // asLogMessage( "PENDING NETWORK BINDING: UNIMPLEMNTED, returning TRUE" );
    // daveti: we have no idea if this response is related with our prev request
    // as we do not trace the ARP request from the kernel. However, based on the
    // assumption that all the corresponding response should have the target as
    // arpsecd, we will determine if this response is the one we are waiting for.
    // NOTE: this assumption includes all the responses with the same target....

    // Check if the network address is ourselves
    asLogMessage("ascPendingNetworkBinding: Debug - addr [%s], asLocalNet [%s]",
		addr, ascLocalNet);
    if (strcasecmp(addr, ascLocalNet) == 0)
    	return 1;

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascPendingMediaBinding
// Description  : determine whether this response is in relation to prev request
//
// Inputs       : addr - the address to check
// Outputs      : 1 if successful, 0 if failure
// Dev		: daveti

int ascPendingMediaBinding( AsMediaAddress addr )  {
    // For now, just return pending for everything
    // asLogMessage( "PENDING MEDIA BINDING: UNIMPLEMNTED, returning TRUE" );
    // daveti: the same comments above, Man~!
    
    // Check if the MAC address is ourselves
    asLogMessage("ascPendingMediaBinding: Debug - addr [%s], asLocalMedia [%s]",
		addr, ascLocalMedia);
    if (strcasecmp(addr, ascLocalMedia) == 0)
	return 1;

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascAddNeighbor
// Description  : Add the MAC/IP binding into the ARP cache
//
// Inputs       : arp, ip, iface
// Outputs      : 0 if successful, -1 if failure
// Dev          : daveti

int ascAddNeighbor(struct libnet_arp_hdr *arp, u_int32_t ip, char *iface) 
{
  struct fixed_ether_arp *earp;
  u_int32_t spa,tpa;

  earp = (struct fixed_ether_arp *) arp;
  spa = *(u_int32_t *)&earp->arp_spa;
  tpa = *(u_int32_t *)&earp->arp_tpa;

  if (spa == ip) {
    /* do nothing, you already know what is your own IP and MAC */
    asLogMessage("ascAddNeighbor: Info - Reply with my address will be ignored\n");
    return -1;
  }

  if (tpa != ip) {
    asLogMessage("ascAddNeighbor: Info - Reply not for me\n");
    return -1;
  }

  /* Add the binding */
  neigh_add(earp->arp_sha, spa, iface, NUD_REACHABLE);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascDelNeighbor
// Description  : Delete the MAC/IP binding into the ARP cache
//
// Inputs       : arp, ip, iface
// Outputs      : 0 if successful, -1 if failure
// Dev          : daveti

int ascDelNeighbor(struct libnet_arp_hdr *arp, u_int32_t ip, char *iface)
{
  struct fixed_ether_arp *earp;
  u_int32_t spa;

  earp = (struct fixed_ether_arp *) arp;
  spa = *(u_int32_t *)&earp->arp_spa;

  /* Remove the binding */
  neigh_remove(earp->arp_sha, spa, iface);

  return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpRequest
// Description  : process a received ARP request message with extension for pcap
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessArpRequest( askRelayMessage *msg,
			struct libnet_arp_hdr *arp,
			u_int32_t ip,
			libnet_t *iface )
{
    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char media[MAX_MEDADDR_LENGTH];
    AsMediaAddress med = media;

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_REQ ) {
	asLogMessage( "ascProcessArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.network, ascLocalNet ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	// asLogMessage( "ascProcessArpRequest: UNIMPLEMNTED ARP RESPONSE, waiting for kernel" );
	// ret = -1;
	// daveti
	ret = ascProcessArpRequestPcap(arp, ip, iface);
	if (ret == -1)
		asLogMessage("ascProcessArpRequest: Error on ascProcessArpRequestPcap()");
	else
		asLogMessage("ascProcessArpRequest: Info - ARP reply sent");


    } else {

	// Check to see if we have a good binding for this
/* No logic
	asStartMetricsTimer();
	if ( aslFindValidMediaBinding( msg->target.network, med, now ) )  {
	    asLogMessage( "Found good ARP REQ binding [%s->%s]", msg->target.network, med );
	} else {
	    asLogMessage( "Failed to find good ARP REQ binding [%s]", msg->target.network );
	}
	asStopMetricsTimer( "ARP Binding" );
*/

    }

    // Return the return code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpResponse
// Description  : process a received ARP response message with extension for pcap
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessArpResponse( askRelayMessage *msg,
			struct libnet_arp_hdr *arp,
			u_int32_t ipp,
			char *iface)
{
    //Local variables
    int ret = 0;
    int bound = 0;
    int trusted = 0;
    AsTime now = time(NULL);
    char mac[ARPSEC_NETLINK_STR_MAC_LEN];
    char ip[ARPSEC_NETLINK_STR_IPV4_LEN];
    timer_queue_msg *tqm;

    // Do a quick sanity check
    if ( msg->op != RFC_826_ARP_RES ) {
	asLogMessage( "ascProcessArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // Convert the logic MAC/IPv4 to normal string MAC/IPv4
    asnLogicMacToStringMac(msg->sndr, mac);
    asnLogicIpToStringIp(msg->sndr_net, ip);

    // If this was a response we were looking for
    //if ( ascPendingNetworkBinding(msg->target.network) ) {
    // daveti: msg->target.network is saving the sender's IPv4!
    if (ascPendingNetworkBinding(msg->dest_net))
    {
	asLogMessage("ascProcessArpResponse: Info - pending ARP response for arpsecd");

	// daveti: Before running the logic and updating the ARP cache, let's check the
	// black list for MAC at first. If the MAC is in the black list,
	// we do nothing except logging the warning for this malicious MAC.
	// Otherwise, move on as we do usually.
	// daveti: if ascForceAttestFlag is enabled, even though this is the MAC in the
	// black list, we will move on doing attestation to avoid potential DDoS/DoS attack.
	// NOTE: ascForceAttestFlag eventually should work both for black and white list.
	// However, to make it flexible for the hybrid network, we trust white list anyway,
	// as these machines may not have TPM within their machines.
	if (ascForceAttestFlag == 0)
	{
		pthread_mutex_lock(&timer_queue_mutex);
		tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
		pthread_mutex_unlock(&timer_queue_mutex);
		if (tqm != NULL)
		{
			asLogMessage("ascProcessArpResponse: Warning - got ARP response from malicious MAC [%s]",
				mac);
			return -1;
		}
	}

	// daveti: After checking the black list, let's check the White List, to see
	// if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
	// This is necessary in the real network env. As we need to trust the DNS and
	// gateway within the network even if they do not have TPMs.
	// NOTE: this is a security hole...ascForceAttestFlag should be considered in future!
//ONLY TPM here -daveti
	trusted = aswlCheckMacIpTrusted(mac, ip);
	if (trusted)
	{
		asLogMessage("ascProcessArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
			mac, ip);
		//Add the binding directly without invoking TPM
		ret = ascAddNeighbor(arp, ipp, iface);
		return ret;
	}
		

	// Else: we have to invoke the TPM here

            ret = ascAddNeighbor(arp, ipp, iface);
            if (ret == -1)
                asLogMessage("ascProcessArpResponse: Error on ascAddNeighbor() for temp");
            else {
                asLogMessage("ascProcessArpResponse: Info - ARP cache updated for temp");
            }

            // Go attest the system
            //if( astAttestSystem(msg->source) ) {
            if (astAttestSystem(msg))
            {
                asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES",
                        msg->source, now );

                // daveti: once the attestation fails, the binding needs
                // to be removed from the ARP cache.
                ret = ascDelNeighbor(arp, ipp, iface);
                if (ret == -1)
                        asLogMessage("ascProcessArpResponse: Error on ascDelNeighbor()");
                else
                        asLogMessage("ascProcessArpResponse: Info - ARP cache updated (entry removed)");

                // daveti: Add this MAC into the black list to prevent
                // future ARP spoofing and to reduce the overhead of talking
                // with the kernel.
                if (ascForceAttestFlag == 0)
                {
                        pthread_mutex_lock(&timer_queue_mutex);
                        ret = tq_create_add_msg(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
                        pthread_mutex_unlock(&timer_queue_mutex);
                        if (ret != 0)
                                asLogMessage("ascProcessArpResponse: Error on tq_create_add_msg for MAC [%s]",
                                        mac);
                        asLogMessage("ascProcessArpResponse: Info - add MAC [%s] into the MAC Black List", mac);
                }

                return( -1 );
            }

            if (ascEnableCacheFlag == 1)
            {
                asLogMessage("ascProcessArpResponse: Info - add MAC/IP [%s|%s] into the white list", mac, ip);
                if (aswlAddMacIpTrusted(mac, ip) == -1)
                        asLogMessage("ascProcessArpResponse: Error on aswlAddMacIpTrusted()");
            }
	    return 0;
//ONLY TPM end - daveti



	// Check the source system
	// daveti: add the forceAttestFlag for UT
	// daveti: add the trusted flag for White List
	if ( (!trusted) && ((!aslSystemTrusted(msg->source, now)) || (ascForceAttestFlag == 1)) )  {

	    // daveti: we are not sure if the binding is in the ARP cache or not.
	    // For the case here, it is much more possible that the binding is
	    // removed by the kernel because of timer expiration.

	    // daveti: Before attesting, the binding needs to be
	    // added into ARP cache temperarily.
            ret = ascAddNeighbor(arp, ipp, iface);
            if (ret == -1)
                asLogMessage("ascProcessArpResponse: Error on ascAddNeighbor() for temp");
            else {
                asLogMessage("ascProcessArpResponse: Info - ARP cache updated for temp");
		bound = 1;
	    }

	    // Go attest the system
	    //if( astAttestSystem(msg->source) ) {
	    if (astAttestSystem(msg))
	    {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );

		// daveti: once the attestation fails, the binding needs
		// to be removed from the ARP cache.
        	ret = ascDelNeighbor(arp, ipp, iface);
        	if (ret == -1)
                	asLogMessage("ascProcessArpResponse: Error on ascDelNeighbor()");
        	else
                	asLogMessage("ascProcessArpResponse: Info - ARP cache updated (entry removed)");

                // daveti: Add this MAC into the black list to prevent
                // future ARP spoofing and to reduce the overhead of talking
                // with the kernel.
		if (ascForceAttestFlag == 0)
		{
			pthread_mutex_lock(&timer_queue_mutex);
			ret = tq_create_add_msg(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
			pthread_mutex_unlock(&timer_queue_mutex);
			if (ret != 0)
				asLogMessage("ascProcessArpResponse: Error on tq_create_add_msg for MAC [%s]",
					mac);
			asLogMessage("ascProcessArpResponse: Info - add MAC [%s] into the MAC Black List", mac);
		}

		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );

	    // Add the MAC/IP into the whitelist (cache) if the attestation succeeds
	    // Currently only ARP response has caching functionality
	    //  - RARP response is not implemented yet!
	    if (ascEnableCacheFlag == 1)
	    {
		asLogMessage("ascProcessArpResponse: Info - add MAC/IP [%s|%s] into the white list", mac, ip);
		if (aswlAddMacIpTrusted(mac, ip) == -1)
			asLogMessage("ascProcessArpResponse: Error on aswlAddMacIpTrusted()");
	    }
	}

	// Ok, now trusted, add binding statement
	asStartMetricsTimer();
	aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
	asStopMetricsTimer( "ARP add binding ");
	asLogMessage( "Successfully processed ARP RES [%s->%s]", msg->target.network, msg->binding.media);

	// daveti: add the binding into ARP cache
	if (bound == 1)
		asLogMessage("ascProcessArpResponse: Info - ARP cache updated");
	else
	{
		ret = ascAddNeighbor(arp, ipp, iface);
		if (ret == -1)
			asLogMessage("ascProcessArpResponse: Error on asnAddBindingToArpCache()");
		else
			asLogMessage("ascProcessArpResponse: Info - ARP cache updated");
	}

    } else {

	asLogMessage("ascProcessArpResponse: Info - non-pending ARP response for arpsecd");

//NO LOGIC
return 0;

	// daveti: Check the black list to see if we have the MAC already.
	// If so, no logic running or ARP cache update will happen. Otherwise,
	// run into the logic verification.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_MAC, mac, TIMER_THREAD_BLACKLIST_MAC);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
                	asLogMessage("ascProcessArpResponse: Warning - got ARP response from malicious MAC [%s]",
                                mac);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

//NO LOGIC - just add it
ret = ascAddNeighbor(arp, ipp, iface);
return ret;


	// Check the source system
	// daveti: add the trusted flag for the white list
	if ( (trusted) || (aslSystemTrusted(msg->source, now)) )  {

	    // daveti: As we will not use white list here, we assume the
	    // nice remote machine would not generate the ARP response
	    // storm given the short time...
	
	    // Ok, now trusted, add binding statement
	    aslAddBindingStatement( msg->source, msg->binding.media, msg->target.network, now );
	    asLogMessage( "Successfully processed foriegn ARP RES [%s->%s]", 
		    msg->target.network, msg->binding.media);

	    // daveti: add the binding into ARP cache
            ret = ascAddNeighbor(arp, ipp, iface);
            if (ret == -1)
		asLogMessage("ascProcessArpResponse: Error on asnAddBindingToArpCache()");
	    else
            	asLogMessage("ascProcessArpResponse: Info - ARP cache updated");

	} else {

	    // Foreign IP from untrusted system
	    asLogMessage( "ascProcessArpResponse: ignoring ARP RES for foreign IP [%s]", 
		    msg->target.network );

	    // daveti: Could think about adding the MAC into the black list. However,
	    // current black list only works for the ones failed attestation. As there
	    // is no attestation here, we have no idea if this MAC is really bad or not.
	    // We could add the MAC into the black list, which improves the ARP security
	    // to certain extent...But now, let's leave it as it is:)
	}
    }

    // Otherwise this is intended for somebody else
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpRequest
// Description  : process a received RARP request message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessRArpRequest( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    AsTime now = time(NULL);
    char network[MAX_NETADDR_LENGTH];
    AsNetworkAddress net = network;

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RREQ ) {
	asLogMessage( "ascProcessRArpRequest: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // If the local interface is the one that we are looking for
    if ( strcmp( msg->target.media, ascLocalMedia ) == 0 ) {

	// TODO: implement the arp response tickle of the kernel when we have it
	// asLogMessage( "ascProcessRArpRequest: UNIMPLEMNTED RARP RESPONSE, waiting for kernel" );
	// ret = -1;
        ret = asnReplyToArpRequest(msg);
        if (ret == -1)
                asLogMessage("ascProcessRArpRequest: Error on asnReplyToArpRequest()");
        else
                asLogMessage("ascProcessRArpRequest: Info - ARP reply sent");

    } else {

	// Check to see if we have a good binding for this
	asStartMetricsTimer();
	if ( aslFindValidNetworkBinding( net, msg->target.media, now ) )  {
	    asLogMessage( "Found good ARP binding {%s->%s]", msg->target.media, net );
	} else {
	    asLogMessage( "Failed to find good RARP REQ binding [%s]", msg->target.media );
	}
	asStopMetricsTimer( "RARP Binding" );

    }

    // Return the processing code
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessRArpResponse
// Description  : process a received RARP response message
//
// Inputs       : msg - received message
// Outputs      : 0 if successful, -1 if failure
// Dev		: daveti

int ascProcessRArpResponse( askRelayMessage *msg ) {

    //Local variables
    int ret = 0;
    int bound = 0;
    int trusted = 0;
    AsTime now = time(NULL);
    char mac[ARPSEC_NETLINK_STR_MAC_LEN];
    char ip[ARPSEC_NETLINK_STR_IPV4_LEN];
    timer_queue_msg *tqm;

    // Do a quick sanity check
    if ( msg->op != RFC_903_ARP_RRES ) {
	asLogMessage( "ascProcessRArpResponse: Insane relay message opcode [%d]", msg->op );
	exit( -1 );
    }

    // Convert the logic MAC/IPv4 to normal string MAC/IPv4
    asnLogicMacToStringMac(msg->sndr, mac);
    asnLogicIpToStringIp(msg->sndr_net, ip);

    // If this was a response we were looking for
    //if ( ascPendingMediaBinding(msg->target.media) ) {
    if (ascPendingMediaBinding(msg->dest))
    {
	asLogMessage("ascProcessRArpResponse: Info - pending RARP response for arpsecd");

        // daveti: Before running the logic and updating the ARP cache, let's check the
        // black list for MAC at first. If the MAC is in the black list,
        // we do nothing except logging the warning for this malicious MAC.
        // Otherwise, move on as we do usually.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
                	asLogMessage("ascProcessRArpResponse: Warning - got ARP response from malicious IP [%s]",
                                ip);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessRArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

	// Check the source system
	// daveti: add the forceAttestFlag for UT
	if ( (!trusted) && ((!aslSystemTrusted(msg->source, now)) || (ascForceAttestFlag == 1)) )  {

            // daveti: Before attesting, the binding needs to be
            // added into ARP cache temperarily.
            ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
                asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache() for temp");
            else {
                asLogMessage("ascProcessRArpResponse: Info - ARP cache updated for temp");
		bound = 1;
	    }

	    // Go attest the system
	    //if( astAttestSystem(msg->source) ) {
	    if (astAttestSystem(msg))
	    {
		asLogMessage( "Unable to attest system [%s] at time [%lu], ignoring ARP RES", 
			msg->source, now );

                // daveti: once the attestation fails, the binding needs
                // to be removed from the ARP cache.
                ret = asnDelBindingInArpCache(msg);
                if (ret == -1)
                        asLogMessage("ascProcessRArpResponse: Error on asnDelBindingInArpCache()");
                else
                        asLogMessage("ascProcessRArpResponse: Info - ARP cache updated (entry removed)");

		// daveti: add the malicious IP into the black list to
		// prevent further spoofing and the overhead talking with kernel.
		if (ascForceAttestFlag == 0)
		{
                	pthread_mutex_lock(&timer_queue_mutex);
                	ret = tq_create_add_msg(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
                	pthread_mutex_unlock(&timer_queue_mutex);
                	if (ret != 0)
                        	asLogMessage("ascProcessRArpResponse: Error on tq_create_add_msg for IP [%s]",
                                        ip);
			asLogMessage("ascProcessRArpResponse: Info - add the IP [%s] into the IP Black List", ip);
		}

		return( -1 );
	    }

	    // Add the attestation time to the logic
	    aslAddTrustStatement( msg->source, now );
	}

	// Now add the binding statement
	asStartMetricsTimer();
	aslAddBindingStatement( msg->source, msg->target.media, msg->binding.network, now );
	asLogMessage( "Successfully processed RARP RES [%s->%s]", msg->target.media, msg->binding.network);
	asStopMetricsTimer( "RARP add binding ");

        // daveti: add the binding into ARP cache
	if (bound == 1)
		asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");
	else
	{
        	ret = asnAddBindingToArpCache(msg);
        	if (ret == -1)
                	asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache()");
        	else
                	asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");
	}

    } else {

	asLogMessage("ascProcessRArpResponse: Info - non-pending RARP response for arpsecd");

        // daveti: Check the black list to see if we have the MAC already.
        // If so, no logic running or ARP cache update will happen. Otherwise,
        // run into the logic verification.
	if (ascForceAttestFlag == 0)
	{
        	pthread_mutex_lock(&timer_queue_mutex);
        	tqm = tq_get_msg_on_str(TIMER_QUEUE_MSG_TYPE_IPV4, ip, TIMER_THREAD_BLACKLIST_IPV4);
        	pthread_mutex_unlock(&timer_queue_mutex);
        	if (tqm != NULL)
        	{
			asLogMessage("ascProcessRArpResponse: Warning - got ARP response from malicious IP [%s]",
                                ip);
                	return -1;
		}
        }

        // daveti: After checking the black list, let's check the White List, to see
        // if the MAC/IP is the one we trust. If it is, the logic layer will be bypassed.
        // This is necessary in the real network env. As we need to trust the DNS and
        // gateway within the network even if they do not have TPMs.
        // NOTE: this is a security hole...
        trusted = aswlCheckMacIpTrusted(mac, ip);
        if (trusted)
                asLogMessage("ascProcessRArpResponse: Info - found trusted MAC/IPv4 [%s|%s] in the white list",
                        mac, ip);

	// Check the source system
	if ( (trusted) || (aslSystemTrusted(msg->source, now)) )  {

	    // Now add the binding statement
	    aslAddBindingStatement( msg->source, msg->target.media, msg->binding.network, now );
	    asLogMessage( "Successfully processed foreign RARP RES [%s->%s]", 
		    msg->target.media, msg->binding.network);

            // daveti: add the binding into ARP cache
	    ret = asnAddBindingToArpCache(msg);
            if (ret == -1)
                    asLogMessage("ascProcessRArpResponse: Error on asnAddBindingToArpCache()");
            else
                    asLogMessage("ascProcessRArpResponse: Info - ARP cache updated");


	} else {

	    // Ignore message
	    asLogMessage( "ascProcessRArpResponse: ignoring RARP RES for foreign IP [%s]", 
		    msg->target.network );
	}
    }

    // Otherwise this is intended for somebody else
    return( ret );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessMessage
// Description  : process a received ARP message
//
// Inputs       : msg - received message
// Outputs      : pointer to the message or NULL if failure

int ascProcessMessage( askRelayMessage *msg ) {
/*
NOT used for pcap

    // Log the fact that we got the message
    int ret;
    char buf[256];
// daveti: add timing
struct timeval tpstart,tpend;
float timeuse = 0;

    asLogMessage( "Processing ARP from kernel [%s]", askMessageToString(msg,buf, 256) );


    // If we are the soruce, just ignore
    if ( strcmp(msg->sndr, ascLocalMedia) == 0 ) {
	asLogMessage( "Ignoring message sent mby local stack [%s]", askMessageToString(msg,buf, 256) );
	return( 0 );
    }

    // Figure out which message we are sending
    switch (msg->op) {
    
	case RFC_826_ARP_REQ:    // ARP Request
	ret = ascProcessArpRequest( msg );
	break;

	case RFC_826_ARP_RES:    // ARP Response
//daveti: timing for ARP response processing
{
gettimeofday(&tpstart,NULL);

	ret = ascProcessArpResponse( msg );

//daveti: end timing
gettimeofday(&tpend,NULL);
timeuse=1000000*(tpend.tv_sec-tpstart.tv_sec)+tpend.tv_usec-tpstart.tv_usec;
timeuse/=1000000;
asLogMessage("arpsec - Total time on ascProcessArpResponse_time() is [%f] ms", timeuse);
}

	break;

	case RFC_903_ARP_RREQ:   // ARP Reverse Request
	ret = ascProcessRArpRequest( msg );
	break;

	case RFC_903_ARP_RRES:   // ARP Reverse Response
	ret = ascProcessRArpResponse( msg );
	break;

	default:
	asLogMessage( "Unknown ARP packet, aborting [%d]", msg->op );
	exit( -1 );
    }

    // Return the return code
    return( ret );
*/
	return 0;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessArpRequestPcap
// Description  : Get the ARP request from the libpcap and reply it directly
//
// Inputs       : pcap parameters....
// Outputs      : int

int ascProcessArpRequestPcap(struct libnet_arp_hdr *arp, u_int32_t ip, libnet_t *iface) 
{
#ifdef MICRO_TEST2
  wl_uint64_t t1,t2,t3,t4,t5,diff;
  wl_current_time(&t1);
#endif
  struct fixed_ether_arp *earp;
  u_int32_t tpa,spa;
  char *spa_str;
  char *tpa_str;
  u_char myaddr[arp->ar_pln];
  int ret = 0;

  earp = (struct fixed_ether_arp *) arp;
  tpa = *(u_int32_t *)&earp->arp_tpa;
 
  if (tpa == ip) {

    /* WL: op is converted to network byte because the rest of the struct 
       is in network byte and that is what send_arp_packet is expecting. 
       it will actually reconvert it to host byte order 
    */
    /* change the ARPOP */
    arp->ar_op = htons(ARPOP_REPLY);  

    /* save my address */
    memcpy(myaddr, earp->arp_tpa, arp->ar_pln);     
      
    /* swap the sender and the target */
    memcpy(earp->arp_tha, earp->arp_sha, arp->ar_hln);
    memcpy(earp->arp_tpa, earp->arp_spa, arp->ar_pln);
   
    /* fill with my addresses */
    memcpy(earp->arp_sha, myMAC, arp->ar_hln);
    memcpy(earp->arp_spa, myaddr, arp->ar_pln);  
    /* MICRO: 2 micro seconds up to this point */

    ret = send_arp_packet(iface, arp, NULL, 0);
    /* MICRO: 50 micro seconds upto this point*/
  }
#ifdef MICRO_TEST2
  wl_current_time(&t3);
  diff = t3-t1;
  printf("total time %llu\n",diff);
#endif

  return ret;
}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascProcessPacket
// Description  : Get the packet from the libpcap and covert it into arpsec msg
//
// Inputs       : pcap parameters....
// Outputs      : void

void ascProcessPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  
#ifdef LOG_TIME
  wl_uint64_t t1,t2,t3,t4,t5,diff;
  wl_current_time(&t1);
#endif

  /* Define pointers for packet's attributes */
  struct libnet_arp_hdr *arp;
  struct fixed_ether_arp *earp;

  arp = (struct libnet_arp_hdr *)(packet + SLL_HEADER_LEN);
  //earp = (struct fixed_ether_arp *)arp;
   
  /* Check that the ARP packet is for IPv4 over Ethernet */
  if ((ntohs(arp->ar_hrd) != ARPHRD_ETHER) || (ntohs(arp->ar_pro) != ETH_P_IP)) {
    return;
  }

  // Convert the arp msg into askRelayMessage
  // which could be called by the ascProcess* routines
  arpsec_rlmsg rlmsg;
  askRelayMessage *msg;
  arpsec_arpmsg *arpmsg_ptr;
  // This may be wrong....
  arpmsg_ptr = (arpsec_arpmsg *)arp;
  memcpy(&(rlmsg.arpsec_arp_msg), arpmsg_ptr, sizeof(arpsec_arpmsg));
  msg = askConvertArpmsg(&rlmsg);

  //process packet according to type
  switch(ntohs(arp->ar_op)) 
    {
    case ARPOP_REQUEST:
      ascProcessArpRequest(msg, arp, myIP, l);
      break;
    
    case ARPOP_REPLY:
      ascProcessArpResponse(msg, arp, myIP, ARPSEC_IF_NAME);
      break;

    default:
      asLogMessage("arpseck_pcap: Error - unsupported ARP opcode [%u]", ntohs(arp->ar_op));
      break;
    }

   // Free the msg
   if (msg != NULL)
	askReleaseBuffer(msg);

#ifdef LOG_TIME
  wl_current_time(&t3);
  diff = t3-t1;
  //printf("total time %llu\n",diff);
#endif

}


////////////////////////////////////////////////////////////////////////////////
//
// Function     : ascControlLoop
// Description  : This is the control loop used for the arpsec deamon
//
// Inputs       : mode - simulate or run normally
// Outputs      : 0 if successful, -1 if no

int ascControlLoop( int mode ) {
    
    // Local variables
    //int rval, nfds, sim, fh;
    int rval, nfds, sim;
    struct timeval next;
    struct timeval tpstart, tpend;
    float timeuse;
    fd_set rdfds, wrfds;
    askRelayMessage *msg;
    // used by pcap
    char errbuf[LIBNET_ERRBUF_SIZE];
#ifdef UNIT_TESTING
    int rnd;
#endif

    // Setup the signal handler 
    signal( SIGINT, ascSigIntHandler );
    signal( SIGHUP, ascSigHupHandler );

    // Intalialize all of the subsystems
    // NOTE: the order of init of subsystems
    // does matters!
    // Sep 21, 2013
    // daveti
    sim = (mode) ? ASKRN_SIMULATION : ASKRN_RELAY;
    if ( aslInitLogic()
	//|| (askInitRelay(sim))
	//|| (asnInitNetlink(sim))
	|| (astdbInitDB(sim))
	|| (aswlInitWL(sim))
	|| (astInitAttest(sim))
	|| (tq_init_queue_all(sim)) )
    {
	// Log and error out of processing
	asLogMessage( "arpsec daemon initalization failed, aborting.\n" );
	return( -1 );
    }

   // daveti: test the bidirectional netlink socket
   // daveti: test the TPM DB
   // daveti: test the White List
   // daveti: test timer queue and create timer thread
   if (sim == ASKRN_RELAY)
   {
	// Setup local info without init Relay
        if (askSetupLocalInfo() == -1)
        {
                asLogMessage("Error on askSetupLocalInfo");
                return -1;
        }
        ascDumpLocalInfo();

	//asnTestNetlink();
	astdbDisplayDB();
	aswlDisplayWL();
	tq_display_queue_all();

	// Create timer thread to control the black lists
	rval = pthread_create(&timer_thread_tid, NULL, timer_thread_main, NULL);
	if (rval != 0)
	{
		asLogMessage("arpsec daemon unable to create timer thread [%s]. Aborting",
				strerror(errno));
		return -1;
	}
	asLogMessage("arpsec daemon timer thread is created");

	// Setup the pcap version
	descr = init_capture();
	if ((l = init_packet_injection(ARPSEC_IF_NAME, errbuf)) == NULL) {
		error_msg(errbuf);
	}
	myIP = get_ip(l);
	myMAC = get_mac(l);
	disable_kernel_arp();
	asLogMessage("arpsec pcap is ready");
   }

    // Loop until done
    ascControlDone = 0;
    while ( !ascControlDone ) {

	// daveti: start pcap
	start_capture(descr, (pcap_handler) ascProcessPacket);

#ifdef UNIT_TESTINAG
	// If unit testing simulating
	if ( mode ) {
	    rnd = as_random(10);
	    if ( rnd > 5 ) {
		testAsLogicInterfaces();
	    }
	}
#endif

    }

    // Close downt the procesing
    aslShutdownLogic();
    if (sim == ASKRN_RELAY)
    {
	pcap_perror(descr,"Capture termiated");
	pthread_kill(timer_thread_tid, SIGTERM);
	//askShutdownRelay();
	//asnShutdownNetlink();
	astdbShutdownDB();
	aswlShutdownWL();
	tpmw_close_tpm();
	tq_destroy_queue_all();
    }

    // Return sucessfully
    return( 0 );
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigIntHandler
// Description	: process the signal for interrupt
//
// Inputs	: the signal (should be SIGINT)
// Outputs	: none

void ascSigIntHandler( int sig ) {
    // Close the capture
    close_capture(descr);
    // Enable the kernel
    enable_kernel_arp();

    ascControlDone = 1;
    asLogMessage( "System received SIGINT signal, processing." );
    return;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function	: ascSigHupHandler
// Description	: process the signal for reset (SIGHUP)
//
// Inputs	: the signal (should be SIGHUP)
// Outputs	: none

void ascSigHupHandler( int sig ) {
    // Close the capture
    close_capture(descr);
    // Enable the kernel
    enable_kernel_arp();

    asLogMessage( "System received SIGHUP signal, processing." );
    return;
}

