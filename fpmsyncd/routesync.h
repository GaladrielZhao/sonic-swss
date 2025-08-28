#ifndef __ROUTESYNC__
#define __ROUTESYNC__

#include "dbconnector.h"
#include "producerstatetable.h"
#include "zmqclient.h"
#include "zmqproducerstatetable.h"
#include "netmsg.h"
#include "linkcache.h"
#include "fpminterface.h"
#include "warmRestartHelper.h"
#include <string.h>
#include <bits/stdc++.h>
#include <linux/version.h>

#include <netlink/route/route.h>

// Add RTM_F_OFFLOAD define if it is not there.
// Debian buster does not provide one but it is neccessary for compilation.
#ifndef RTM_F_OFFLOAD
#define RTM_F_OFFLOAD 0x4000 /* route is offloaded */
#endif

using namespace std;

/* Parse the Raw netlink msg */
extern void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
                                                int len);

namespace swss {

struct NextHopGroup {
    uint32_t id;
    vector<pair<uint32_t,uint8_t>> group;
    string nexthop;
    string intf;
    bool installed;
    NextHopGroup(uint32_t id, const string& nexthop, const string& interface) : installed(false), id(id), nexthop(nexthop), intf(interface) {};
    NextHopGroup(uint32_t id, const vector<pair<uint32_t,uint8_t>>& group) : installed(false), id(id), group(group) {};
};

/* Full nexthop group for zebra and fpm */
struct nh_grp_full {
    uint32_t id;
    uint8_t weight;
    uint32_t num_direct;
};

/* VRF ID type */
typedef uint32_t vrf_id_t;
typedef signed int ifindex_t;

union g_addr {
    struct in_addr ipv4;
    struct in6_addr ipv6;
};

enum nexthop_types_t {
    NEXTHOP_TYPE_IFINDEX = 1,   /* Directly connected */
    NEXTHOP_TYPE_IPV4,    /* IPv4 nexthop */
    NEXTHOP_TYPE_IPV4_IFINDEX,    /* IPv4 nexthop with ifindex */
    NEXTHOP_TYPE_IPV6,    /* IPv6 nexthop */
    NEXTHOP_TYPE_IPV6_IFINDEX,    /* IPv6 nexthop with ifindex */
    NEXTHOP_TYPE_BLACKHOLE,    /* Null0 nexthop */
};

/* LSP types. */
enum lsp_types_t {
    ZEBRA_LSP_NONE = 0,   /* No LSP. */
    ZEBRA_LSP_STATIC = 1, /* Static LSP. */
    ZEBRA_LSP_LDP = 2,    /* LDP LSP. */
    ZEBRA_LSP_BGP = 3,    /* BGP LSP. */
    ZEBRA_LSP_OSPF_SR = 4,  /* OSPF Segment Routing LSP. */
    ZEBRA_LSP_ISIS_SR = 5,  /* IS-IS Segment Routing LSP. */
    ZEBRA_LSP_SHARP = 6,  /* Identifier for test protocol */
    ZEBRA_LSP_SRTE = 7,   /* SR-TE LSP */
    ZEBRA_LSP_EVPN = 8,  /* EVPN VNI Label */
};

enum blackhole_type {
    BLACKHOLE_UNSPEC = 0,
    BLACKHOLE_NULL,
    BLACKHOLE_REJECT,
    BLACKHOLE_ADMINPROHIB,
};

enum seg6local_action_t {
	SEG6_LOCAL_ACTION_UNSPEC       = 0,
	SEG6_LOCAL_ACTION_END          = 1,
	SEG6_LOCAL_ACTION_END_X        = 2,
	SEG6_LOCAL_ACTION_END_T        = 3,
	SEG6_LOCAL_ACTION_END_DX2      = 4,
	SEG6_LOCAL_ACTION_END_DX6      = 5,
	SEG6_LOCAL_ACTION_END_DX4      = 6,
	SEG6_LOCAL_ACTION_END_DT6      = 7,
	SEG6_LOCAL_ACTION_END_DT4      = 8,
	SEG6_LOCAL_ACTION_END_B6       = 9,
	SEG6_LOCAL_ACTION_END_B6_ENCAP = 10,
	SEG6_LOCAL_ACTION_END_BM       = 11,
	SEG6_LOCAL_ACTION_END_S        = 12,
	SEG6_LOCAL_ACTION_END_AS       = 13,
	SEG6_LOCAL_ACTION_END_AM       = 14,
	SEG6_LOCAL_ACTION_END_BPF      = 15,
	SEG6_LOCAL_ACTION_END_DT46     = 16,
};

struct seg6local_flavors_info {
	/* Flavor operations */
	uint32_t flv_ops;

	/* Locator-Block length, expressed in bits */
	uint8_t lcblock_len;
	/* Locator-Node Function length, expressed in bits */
	uint8_t lcnode_func_len;
};

struct seg6local_context {
	struct in_addr nh4;
	struct in6_addr nh6;
	uint32_t table;
	struct seg6local_flavors_info flv;
	uint8_t block_len;
	uint8_t node_len;
	uint8_t function_len;
	uint8_t argument_len;
};

/* SR Policy Headend Behaviors as per RFC 8986 section #5 */
enum srv6_headend_behavior {
	SRV6_HEADEND_BEHAVIOR_H_INSERT,
	SRV6_HEADEND_BEHAVIOR_H_ENCAPS,
	SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED,
	SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2,
	SRV6_HEADEND_BEHAVIOR_H_ENCAPS_L2_RED,
};

struct seg6_seg_stack {
	enum srv6_headend_behavior encap_behavior;
	uint8_t num_segs;
	struct in6_addr seg[0]; /* 1 or more segs */
};

struct nexthop_srv6 {
    /* SRv6 localsid info for Endpoint-behaviour */
    enum seg6local_action_t seg6local_action;
    struct seg6local_context seg6local_ctx;

    /* SRv6 Headend-behaviour */
    struct seg6_seg_stack *seg6_segs;
}

struct NextHopGroupFull {
    uint32_t id;
    uint32_t key;  /* Hash value from zebra for this nhg */
    uint8_t weight;  /* Weight of the nexthop ( for unequal cost ECMP  ) */
    uint8_t flags;
#define NEXTHOP_FLAG_ONLINK     (1 << 3) /* Nexthop should be installed onlink */

    string ifname;  /* Interface name obtained from ifindex */
    vector<struct nh_grp_full> depends;
    vector<struct nh_grp_full> dependents;

    /* begin of hashed data - all fields from here onwards are given to
     * jhash() as one consecutive chunk.  DO NOT create "padding holes".
     * DO NOT insert pointers that need to be deep-hashed.
     *
     * static_assert() below needs to be updated when fields are added
     */
    char _hash_begin[0];

    enum nexthop_types_t type;    /* see above */
    vrf_id_t vrf_id;    /* What vrf is this nexthop associated with? */
    ifindex_t ifindex;    /* Interface index */
    enum lsp_types_t nh_lable_type;    /* Type of label(s), if any */

    /* padding: keep 16 byte alignment here */
    /* Nexthop address
     * make sure all 16 byte for IPv6 are zeroed when putting in an IPv4
     * address since the entire thing is hashed as-is
     */
    union {
        union g_addr gate;
        enum blackhole_type bh_type;
    };
    union g_addr src;
    union g_addr rmap_src; /* Src is set via routemap */

    /* end of hashed data - remaining fields in this struct are not
     * directly fed into jhash().  Most of them are actually part of the
     * hash but have special rules or handling attached.
     */
    char _hash_end[0];

    /* backup, labels and srv6 info are not included yet, let's add later */
    /* backup and label are not in consideration temporarily, let's add srv6 member */

    /* SRv6 information */
    struct nexthop_srv6 *nh_srv6 = nullptr;

    /* Constructor for multi-path NextHopGroupFull */
    NextHopGroupFull(uint32_t id, uint32_t key,
                   const vector<tuple<uint32_t, uint8_t, uint32_t>>& depends,
                   const vector<tuple<uint32_t, uint8_t, uint32_t>>& dependents)
        : id(id), key(key), depends(depends), dependents(dependents) {};

    /* Constructor for singleton NextHopGroupFull */
    NextHopGroupFull(uint32_t id, uint32_t key, enum nexthop_types_t type,
                   vrf_id_t vrf_id, ifindex_t ifindex, enum lsp_types_t label_type,
                   union g_addr gateway, union g_addr src, union g_addr rmap_src,
                   uint8_t weight, uint8_t flags, bool has_srv6, bool has_seg6_segs,
                   const struct nexthop_srv6* nh_srv6_in,
                   const struct seg6_seg_stack* nh_seg6_segs_in,
                   const vector<struct in6_addr>& nh_segs_in)
        : id(id), key(key), type(type), vrf_id(vrf_id), ifindex(ifindex),
          nh_label_type(label_type), gate(gateway), src(src), rmap_src(rmap_src),
          weight(weight), flags(flags), depends({}), dependents({}), nh_srv6(nullptr)
    {
        /* Check if need to allocate the nexthop_srv6 structure */
        if (has_srv6 && nh_srv6_in != nullptr)
        {
            SWSS_LOG_DEBUG("NextHopGroupFull has srv6, allocating...");
            nh_srv6 = (struct nexthop_srv6*)malloc(sizeof(struct nexthop_srv6));
            if (!nh_srv6) {
                SWSS_LOG_ERROR("nh_srv6 allocation fail in NextHopGroupFull construction, abort");
                return;
            }

            memcpy(nh_srv6, nh_srv6_in, sizeof(struct nexthop_srv6));
            SWSS_LOG_DEBUG("NextHopGroupFull finish nh_srv6 initialization");
        }
        else
            SWSS_LOG_DEBUG("NextHopGroupFull does not have srv6 info");

        /* Check if need to allocate the seg6_seg_stack structure */
        if (has_seg6_segs && nh_seg6_segs_in != nullptr)
        {
            SWSS_LOG_DEBUG("NextHopGroupFull has seg6_segs, allocating...");
            size_t total_size = sizeof(struct seg6_seg_stack) +
                                       nh_srv6->seg6_segs->num_segs * sizeof(struct in6_addr);
            nh_srv6->seg6_segs = (struct seg6_seg_stack*)malloc(total_size);
            if (!nh_srv6->seg6_segs) {
                SWSS_LOG_ERROR("seg6_segs allocation fail in NextHopGroupFull construction, abort");
                free(nh_srv6);      /* If fail to allocate segs, we free the nh_srv6 as well */
                nh_srv6 = nullptr;
                return;
            }

            memcpy(nh_srv6->seg6_segs, nh_srv6_in->seg6_segs, sizeof(struct seg6_seg_stack));

            if (nh_srv6->seg6_segs->num_segs > 0)
            {
                for (size_t i = 0; i < nh_srv6->seg6_segs->num_segs; i++)
                {
                    if (i < nh_seg6_segs_in.size())
                        memcpy(&nh_srv6->seg6_segs->seg[i], &nh_segs_in[i], sizeof(struct in6_addr));
                    else
                    {
                        /* If the number between num and segs are not matching */
                        memset(&nh_srv6->seg6_segs->seg[i], 0, sizeof(in6_addr));
                        SWSS_LOG_DEBUG("Size between num_segs and vector segs is not matching, num_segs %d, vector size %d",
                                               nh_srv6->seg6_segs->num_segs, nh_seg6_segs_in.size());
                    }
                }
            }
        }
    }

    /* Destructor of NextHopGroupFull */
    ~NextHopGroupFull()
    {
        if (nh_srv6 != nullptr)
        {
            if (nh_srv6->seg6_segs != nullptr)
            {
                SWSS_LOG_DEBUG("Free seg6_segs in NextHopGroupFull Destructor");
                free(nh_srv6->seg6_segs);
            }
            SWSS_LOG_DEBUG("Free nh_srv6 in NextHopGroupFull Destructor");
            free(nh_srv6);
        }

        SWSS_LOG_DEBUG("NextHopGroupFull destroyed.");
    }
};

/* Path to protocol name database provided by iproute2 */
constexpr auto DefaultRtProtoPath = "/etc/iproute2/rt_protos";

class RouteSync : public NetMsg
{
public:
    enum { MAX_ADDR_SIZE = 64 };

    RouteSync(RedisPipeline *pipeline);

    virtual void onMsg(int nlmsg_type, struct nl_object *obj);

    virtual void onMsgRaw(struct nlmsghdr *obj);

    void setSuppressionEnabled(bool enabled);

    bool isSuppressionEnabled() const
    {
        return m_isSuppressionEnabled;
    }

    /* Helper method to set route table with warm restart support */
    void setRouteWithWarmRestart(const std::string& key, const std::vector<FieldValueTuple>& fvVector,
                                 shared_ptr<ProducerStateTable> table, const std::string& cmd = SET_COMMAND);

    void onRouteResponse(const std::string& key, const std::vector<FieldValueTuple>& fieldValues);

    void onWarmStartEnd(swss::DBConnector& applStateDb);

    /* Mark all routes from DB with offloaded flag */
    void markRoutesOffloaded(swss::DBConnector& db);

    void onFpmConnected(FpmInterface& fpm)
    {
        m_fpmInterface = &fpm;
    }

    void onFpmDisconnected()
    {
        m_fpmInterface = nullptr;
    }

    WarmStartHelper& getWarmStartHelper()
    {
        return m_warmStartHelper;
    }

private:
    /* ZMQ client */
    shared_ptr<ZmqClient> m_zmqClient;
    /* regular route table */
    shared_ptr<ProducerStateTable> m_routeTable;
    /* label route table */
    shared_ptr<ProducerStateTable> m_label_routeTable;
    /* vnet route table */
    ProducerStateTable  m_vnet_routeTable;
    /* vnet vxlan tunnel table */  
    ProducerStateTable  m_vnet_tunnelTable;
    /* Warm start helper */
    WarmStartHelper m_warmStartHelper;
    /* srv6 mySid table */
    ProducerStateTable m_srv6MySidTable; 
    /* srv6 sid list table */
    ProducerStateTable m_srv6SidListTable; 
    struct nl_cache    *m_link_cache;
    struct nl_sock     *m_nl_sock;
    /* nexthop group table */
    ProducerStateTable  m_nexthop_groupTable;
    map<uint32_t,NextHopGroup> m_nh_groups;

    bool                m_isSuppressionEnabled{false};
    FpmInterface*       m_fpmInterface {nullptr};

    /* Handle regular route (include VRF route) */
    void onRouteMsg(int nlmsg_type, struct nl_object *obj, char *vrf);

    /* Handle label route */
    void onLabelRouteMsg(int nlmsg_type, struct nl_object *obj);

    void parseEncap(struct rtattr *tb, uint32_t &encap_value, string &rmac);

    void parseEncapSrv6SteerRoute(struct rtattr *tb, string &vpn_sid, string &src_addr);

    bool parseSrv6MySid(struct rtattr *tb[], string &block_len,
                           string &node_len, string &func_len,
                           string &arg_len, string &action, string &vrf,
                           string &adj);

    bool parseSrv6MySidFormat(struct rtattr *tb, string &block_len,
                                 string &node_len, string &func_len,
                                 string &arg_len);

    void parseRtAttrNested(struct rtattr **tb, int max,
                 struct rtattr *rta);

    char *prefixMac2Str(char *mac, char *buf, int size);


    /* Handle prefix route */
    void onEvpnRouteMsg(struct nlmsghdr *h, int len);

    /* Handle routes containing an SRv6 nexthop */
    void onSrv6SteerRouteMsg(struct nlmsghdr *h, int len);

    /* Handle SRv6 MySID */
    void onSrv6MySidMsg(struct nlmsghdr *h, int len);

    /* Handle vnet route */
    void onVnetRouteMsg(int nlmsg_type, struct nl_object *obj, string vnet);

    /* Get interface name based on interface index */
    virtual bool getIfName(int if_index, char *if_name, size_t name_len);

    /* Get interface if_index based on interface name */
    rtnl_link* getLinkByName(const char *name);

    void getEvpnNextHopSep(string& nexthops, string& vni_list,  
                       string& mac_list, string& intf_list);

    void getEvpnNextHopGwIf(char *gwaddr, int vni_value,
                          string& nexthops, string& vni_list,
                          string& mac_list, string& intf_list,
                          string rmac, string vlan_id);

    virtual bool getEvpnNextHop(struct nlmsghdr *h, int received_bytes, struct rtattr *tb[],
                        string& nexthops, string& vni_list, string& mac_list,
                        string& intf_list);

    bool getSrv6SteerRouteNextHop(struct nlmsghdr *h, int received_bytes,
                        struct rtattr *tb[], string &vpn_sid, string &src_addr);

    /* Get next hop list */
    void getNextHopList(struct rtnl_route *route_obj, string& gw_list,
                        string& mpls_list, string& intf_list);

    /* Get next hop gateway IP addresses */
    string getNextHopGw(struct rtnl_route *route_obj);

    /* Get next hop interfaces */
    string getNextHopIf(struct rtnl_route *route_obj);

    /* Get next hop weights*/
    string getNextHopWt(struct rtnl_route *route_obj);

    /* Sends FPM message with RTM_F_OFFLOAD flag set to zebra */
    bool sendOffloadReply(struct nlmsghdr* hdr);

    /* Sends FPM message with RTM_F_OFFLOAD flag set to zebra */
    bool sendOffloadReply(struct rtnl_route* route_obj);

    /* Sends FPM message with RTM_F_OFFLOAD flag set for all routes in the table */
    void sendOffloadReply(swss::DBConnector& db, const std::string& table);

    /* Get encap type */
    uint16_t getEncapType(struct nlmsghdr *h);

    const char *mySidAction2Str(uint32_t action);

    /* Handle Nexthop message */
    void onNextHopMsg(struct nlmsghdr *h, int len);
    /* Get next hop group key */
    const string getNextHopGroupKeyAsString(uint32_t id) const;
    void installNextHopGroup(uint32_t nh_id);
    void deleteNextHopGroup(uint32_t nh_id);
    void updateNextHopGroupDb(const NextHopGroup& nhg);
    void getNextHopGroupFields(const NextHopGroup& nhg, string& nexthops, string& ifnames, string& weights, uint8_t af = AF_INET);

    /* Handle Full Nexthop Group message */
    void onNextHopFullMsg(struct nlmsghdr *h, int len);
    /* Get next hop group (full) key */
    /* Not sure if need this because decode function would pass table the whole */
};

}

#endif
