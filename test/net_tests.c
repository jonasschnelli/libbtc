#include "utest.h"
#include <btc/net.h>
#include <btc/netspv.h>

extern void btc_net_test();

btc_bool timer_cb(btc_node *node, uint64_t *now)
{
    if (node->time_started_con + 12 < *now)
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

    /* create a invalid node */
    btc_node *node_wrong = btc_node_new();
    u_assert_int_eq(btc_node_set_ipport(node_wrong, "0.0.0.1:1"), true);

    /* create a invalid node to will run directly into a timeout */
    btc_node *node_timeout_direct = btc_node_new();
    u_assert_int_eq(btc_node_set_ipport(node_timeout_direct, "127.0.0.1:1234"), true);

    /* create a invalid node to will run indirectly into a timeout */
    btc_node *node_timeout_indirect = btc_node_new();
    u_assert_int_eq(btc_node_set_ipport(node_timeout_indirect, "8.8.8.8:8333"), true);

    /* create a node */
    btc_node *node = btc_node_new();
    u_assert_int_eq(btc_node_set_ipport(node, "176.9.45.239:8333"), true);

    /* create a node group */
    btc_node_group* group = btc_node_group_new(NULL);
    group->desired_amount_connected_nodes = 1;

    /* add the node to the group */
    btc_node_group_add_node(group, node_wrong);
    btc_node_group_add_node(group, node_timeout_direct);
    btc_node_group_add_node(group, node_timeout_indirect);
    btc_node_group_add_node(group, node);

    /* set the timeout callback */
    group->periodic_timer_cb = timer_cb;

    /* set a individual log print function */
    group->log_write_cb = default_write_log;

    /* connect to the next node */
    btc_node_group_connect_next_nodes(group);

    /* start the event loop */
    btc_node_group_event_loop(group);

    /* cleanup */
    btc_node_group_free(group); //will also free the nodes structures from the heap
}
