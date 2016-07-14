#include "utest.h"
#include <btc/net.h>
#include <btc/netspv.h>

extern void btc_net_test();

void test_net()
{
    enum logdb_error error;
    btc_spv_client* client = btc_spv_client_new();
    btc_spv_client_load(client, NULL, &error);
    btc_node_group* group = btc_node_group_new(NULL);
    group->ctx = client;
    btc_net_set_spv(group);

    vector *ips = vector_new(1, free);
    btc_net_spv_get_peers_from_dns(NULL, ips, AF_INET);
    //u_assert_int_eq(btc_node_setaddr_str(node, "127.0.0.1:18444"), true);
    for(size_t i = 0; i<ips->len; i++)
    {
        btc_node *node = btc_node_new();
        const char *ip = vector_idx(ips, i);
        btc_node_setaddr_str(node, ip);
        btc_node_group_add_node(group, node);
    }
    vector_free(ips, true);
    u_assert_int_eq(btc_node_group_connect_next_nodes(group), true);
    btc_node_group_event_loop(group);

    btc_node_group_free(group);
    btc_spv_client_free(client);
}
