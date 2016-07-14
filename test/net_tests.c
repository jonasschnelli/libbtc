#include "utest.h"
#include <btc/net.h>
#include <btc/netspv.h>

extern void btc_net_test();

btc_bool timer_cb(btc_node *node, uint64_t *now)
{
    if (node->time_started_con + 10 < *now)
        btc_node_disconnect(node);

    /* return true = run internal timer logic (ping, disconnect-timeout, etc.) */
    return true;
}

static int default_write_log(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    return 1;
}

void test_net()
{

    btc_node *node = btc_node_new();
    u_assert_int_eq(btc_node_set_ipport(node, "176.9.45.239:8333"), true);

    btc_node_group* group = btc_node_group_new(NULL);
    btc_node_group_add_node(group, node);
    group->periodic_timer_cb = timer_cb;
    group->log_write_cb = default_write_log;

    btc_node_group_connect_next_nodes(group);
    btc_node_group_event_loop(group);

    btc_node_group_free(group); //will also free the nodes structures from the heap
}
