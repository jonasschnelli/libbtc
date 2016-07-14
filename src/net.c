#include <btc/net.h>

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#include <btc/chain.h>
#include <btc/protocol.h>
#include <btc/buffer.h>
#include <btc/cstr.h>
#include <btc/utils.h>
#include <btc/serialize.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#define UNUSED(x) (void)(x)

void read_cb(struct bufferevent* bev, void* ctx)
{
    struct evbuffer* input = bufferevent_get_input(bev);
    size_t length = evbuffer_get_length(input);

    btc_node *node = (btc_node *)ctx;

    // expand the cstring buffer if required
    cstr_alloc_minsize(node->recvBuffer, node->recvBuffer->len+length);

    // copy direct to cstring, avoid another heap buffer
    evbuffer_copyout(input, node->recvBuffer->str+node->recvBuffer->len, length);
    node->recvBuffer->len += length;

    // drain the event buffer
    evbuffer_drain(input, length);

    struct const_buffer buf = {node->recvBuffer->str, node->recvBuffer->len};
    btc_p2p_msg_hdr hdr;
    char *read_upto = NULL;

    do {
        //check if message is complete
        if (buf.len < BTC_P2P_HDRSZ)
        {
            break;
        }

        btc_p2p_deser_msghdr(&hdr, &buf);
        if (buf.len < hdr.data_len)
        {
            //if we haven't read the whole message, continue and wait for the next chunk
            break;
        }
        if (buf.len >= hdr.data_len)
        {
            //at least one message is complete

            struct const_buffer cmd_data_buf = {buf.p, buf.len};
            btc_node_parse_message(node, &hdr, &cmd_data_buf);

            //skip the size of the whole message
            buf.p += hdr.data_len;
            buf.len -= hdr.data_len;

            read_upto = (void *)buf.p;
        }
        if (buf.len == 0)
        {
            //if we have "consumed" the whole buffer
            node->recvBuffer->len = 0;
            break;
        }
    } while(1);

    if (read_upto != NULL && node->recvBuffer->len != 0 && read_upto != (node->recvBuffer->str + node->recvBuffer->len))
    {
        char *end = node->recvBuffer->str + node->recvBuffer->len;
        size_t available_chunk_data = end - read_upto;
        //partial message
        cstring *tmp = cstr_new_buf(read_upto, available_chunk_data);
        cstr_free(node->recvBuffer, true);
        node->recvBuffer = tmp;
    }
}

void write_cb(struct bufferevent* ev, void* ctx)
{
    UNUSED(ev);
    UNUSED(ctx);
}

void event_cb(struct bufferevent* ev, short type, void* ctx)
{
    UNUSED(ev);
    btc_node *node = (btc_node *)ctx;
    printf("Event Callback on node %d\n", node->nodeid);
    printf("Connected nodes: %d\n", btc_node_group_amount_of_connected_nodes(node->nodegroup));

    if (((type & BEV_EVENT_TIMEOUT) != 0) ||
        ((type & BEV_EVENT_EOF) != 0) ||
        ((type & BEV_EVENT_ERROR) != 0))
    {
        printf("Timeout or error node %d.\n", node->nodeid);
        node->state = 0;
        node->state |= NODE_ERRORED;
        btc_node_connection_state_changed(node);
    }
    else if (type & BEV_EVENT_CONNECTED) {
        printf("Successfull connected to node %d.\n", node->nodeid);
        node->state |= NODE_CONNECTED;
        node->state &= ~NODE_CONNECTING;
        node->state &= ~NODE_ERRORED;
        btc_node_connection_state_changed(node);
        /* if callback is set, fire */
    }
}

btc_node* btc_node_new()
{
    btc_node* node;
    node = calloc(1, sizeof(*node));
    node->version_handshake = false;
    node->state = 0;
    node->nonce = 0;
    node->services = 0;

    node->recvBuffer = cstr_new_sz(P2P_MESSAGE_CHUNK_SIZE);

    return node;
}

btc_bool btc_node_setaddr_str(btc_node *node, const char *str_addr)
{
    int outlen = (int)sizeof(node->addr);

    //return true in case of success (0 == no error)
    return (evutil_parse_sockaddr_port(str_addr, &node->addr, &outlen) == 0);
}

void btc_node_free(btc_node *node)
{
    cstr_free(node->recvBuffer, true);
    free(node);
}

void btc_node_free_cb(void *obj)
{
    btc_node *node = (btc_node *)obj;
    free(node);
}

btc_node_group* btc_node_group_new(btc_chain *chainparams)
{
    btc_node_group* node_group;
    node_group = calloc(1, sizeof(*node_group));
    node_group->event_base = event_base_new();
    if (!node_group->event_base) {
        return NULL;
    };

    node_group->nodes = vector_new(1, btc_node_free_cb);
    node_group->chainparams = (chainparams ? chainparams : &btc_chain_main);
    node_group->parse_cmd_cb = NULL;
    strcpy(node_group->clientstr, "libbtc 0.1");

    /* nullify callbacks */
    node_group->postcmd_cb = NULL;
    node_group->node_connection_state_changed_cb = NULL;
    node_group->handshake_done_cb = NULL;

    node_group->desired_amount_connected_nodes = 3;

    return node_group;
}

void btc_node_group_free(btc_node_group *group)
{
    if (!group)
        return;

    if (group->event_base)
    {
        event_base_dispatch(group->event_base);
        event_base_free(group->event_base);
    }

    if (group->nodes)
    {
        vector_free(group->nodes, true);
    }
    free(group);
}

void btc_node_group_event_loop(btc_node_group *group)
{
    event_base_dispatch(group->event_base);
}

void btc_node_group_add_node(btc_node_group *group, btc_node *node)
{
    vector_add(group->nodes, node);
    node->nodegroup = group;
    node->nodeid = group->nodes->len;
}

int btc_node_group_amount_of_connected_nodes(btc_node_group *group)
{
    int cnt=0;
    for (size_t i = 0; i < group->nodes->len;i++)
    {
        btc_node *node = vector_idx(group->nodes, i);
        if ((node->state & NODE_CONNECTED) == NODE_CONNECTED)
            cnt++;
    }
    return cnt;
}

btc_bool btc_node_group_connect_next_nodes(btc_node_group *group)
{
    btc_bool connected_at_least_to_one_node = false;
    int connect_amount = group->desired_amount_connected_nodes - btc_node_group_amount_of_connected_nodes(group);
    if (connect_amount <= 0)
        return true;

    for (int i = 0; i < group->nodes->len;i++)
    {
        btc_node *node = vector_idx(group->nodes, i);
        if (
            !((node->state & NODE_CONNECTED) == NODE_CONNECTED)
            &&
            !((node->state & NODE_CONNECTING) == NODE_CONNECTING)
            &&
            !((node->state & NODE_ERRORED) == NODE_ERRORED)
            )
        {
            /* connect to next node */
            node->event_bev = bufferevent_socket_new(group->event_base, -1, BEV_OPT_CLOSE_ON_FREE);
            bufferevent_setcb(node->event_bev, read_cb, write_cb, event_cb, node);
            bufferevent_enable(node->event_bev, EV_READ|EV_WRITE);
            struct timeval tout = { 3, 0};
            bufferevent_set_timeouts(node->event_bev, &tout, &tout);
            if (bufferevent_socket_connect(node->event_bev, (struct sockaddr *)&node->addr, sizeof(node->addr)) < 0)
            {
                /* Error starting connection */
                bufferevent_free(node->event_bev);
                return false;
            }
            node->state |= NODE_CONNECTING;
            connected_at_least_to_one_node = true;
            connect_amount--;
            if (connect_amount <= 0)
                return true;
        }
    }
    /* node group misses a node to connect to */
    return connected_at_least_to_one_node;
}

void btc_node_connection_state_changed(btc_node *node)
{
    if (node->nodegroup->node_connection_state_changed_cb)
        node->nodegroup->node_connection_state_changed_cb(node);

    if ((node->state & NODE_ERRORED) == NODE_ERRORED)
    {
        if (node->event_bev)
        {
            bufferevent_free(node->event_bev);
            node->event_bev = NULL;
        }
        /* connect to more nodes if required */
        if(btc_node_group_amount_of_connected_nodes(node->nodegroup) < node->nodegroup->desired_amount_connected_nodes)
            btc_node_group_connect_next_nodes(node->nodegroup);
    }
    else
        btc_node_send_version(node);
}

void btc_node_send(btc_node *node, cstring *data)
{
    bufferevent_write(node->event_bev, data->str, data->len);
    char *dummy = data->str+4;
    printf("sending message to node %d: %s\n", node->nodeid, dummy);
}

void btc_node_send_version(btc_node *node)
{
    /* get new string buffer */
    cstring *version_msg = cstr_new_sz(256);

    /* copy socket_addr to p2p addr */
    btc_p2p_address fromAddr;
    btc_p2p_address toAddr;
    btc_addr_to_p2paddr(&node->addr, &toAddr);

    /* create version message */
    btc_p2p_msg_version(&fromAddr, &toAddr, node->nodegroup->clientstr, version_msg);

    /* create p2p message */
    cstring *p2p_msg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "version", version_msg->str, version_msg->len);

    /* send message */
    btc_node_send(node, p2p_msg);

    /* cleanup */
    cstr_free(version_msg, true);
    cstr_free(p2p_msg, true);
}

int btc_node_parse_message(btc_node *node, btc_p2p_msg_hdr *hdr, struct const_buffer *buf)
{
    printf("received command from node %d: %s\n",  node->nodeid, hdr->command);
    if (memcmp(hdr->netmagic, node->nodegroup->chainparams->netmagic, sizeof(node->nodegroup->chainparams->netmagic)) != 0)
        return 0;

    /* send the header and buffer to the possible callback */
    /* callback can decide to run the internal base message logic */
    if (!node->nodegroup->parse_cmd_cb || node->nodegroup->parse_cmd_cb(node, hdr, buf))
    {
        if (strcmp(hdr->command, "version") == 0)
        {
            /* confirm version for verack */
            cstring *verack = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "verack", NULL, 0);
            btc_node_send(node, verack);
            cstr_free(verack, true);
        }
        else if (strcmp(hdr->command, "verack") == 0)
        {
            /* complete handshake if verack has been received */
            node->version_handshake = true;

            /* execute callback and inform that the node is ready for custom message logic */
            if (node->nodegroup->handshake_done_cb)
                node->nodegroup->handshake_done_cb(node);
        }
        else if (strcmp(hdr->command, "ping") == 0)
        {
            /* response pings */
            uint64_t nonce = 0;
            deser_u64(&nonce, buf);
            cstring *pongmsg = btc_p2p_message_new(node->nodegroup->chainparams->netmagic, "pong", &nonce, 8);
            btc_node_send(node, pongmsg);
            cstr_free(pongmsg, true);
        }
    }

    if (node->nodegroup->postcmd_cb)
        node->nodegroup->postcmd_cb(node, hdr, buf);

    return true;
}
