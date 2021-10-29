#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ENABLE_SEND 1

#define DPDK_DEBUG 1

#define NUM_MBUFS (4096 -1)   //要求不去满足2的n次方。注意分配时候 小于4K 放到此处，大于4K 的时候另外去分配空间

#define BURST_SIZE 32

int gDpdkPortId = 0;  //端口的Id


struct rte_mbuf *ng_send(struct rte_mempool *mbuf_pool, unsigned char *data, uint16_t length);


#if ENABLE_SEND
static uint32_t gSrcIp; //
static uint32_t gDstIp;
static uint16_t gSrcPort;
static uint16_t gDstPort;
static uint8_t   gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t   gDstMac[RTE_ETHER_ADDR_LEN];
#endif


static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

//端口初始化 eth0
static void ng_init_port(struct rte_mempool *mbuf) {
    //用于检测网卡端口是否有可用
	uint16_t nb_sys_ports = rte_eth_dev_count_avail(); // 程序走不通时候，唯一原因就是端口没有设置。
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No support eth found\n");
	}

	//获取默认网卡端口信息，获取的eth0 原生的信息和dpdk 无关的信息
	struct rte_eth_dev_info dev_info;
	/*
	* @param portid  获取那个网口信息
			 dev_info  网口信息
	*/
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	/*上面是原生dpdk 的信息*/

	/* 配置dpdk网卡端口*/
	/*配置多队列网卡有多少个可以在dpdk中可以使用*/
	const int num_rx_queues = 1;  //设置接受队列的数量
	const int num_tx_queues = 1;  //设置发送队列的数量
    struct rte_eth_conf port_conf = port_conf_default;

	/*配置多队列网卡在dpdk中有多少个可以使用*/
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	/**
	*  0  指的是第零号接受队列
	*  128 随机写的，  每个接受队列的最大接受数量。
	*/
	if ( rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024,
		    rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf ) < 0) {

		rte_exit(EXIT_FAILURE, "Cond not setup RX queue.\n");
	}

#if ENABLE_SEND
    //构建发包队列
    //发包负载
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    //nb_tx_desc要求should be: <= 4096, >= 512, and a product of 1
    if ( rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024,
            rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {

        rte_exit(EXIT_FAILURE, "Cond not setup TX queue.\n");
    }
#endif
    /*端口启动*/
    if (rte_eth_dev_start(gDpdkPortId) < 0) {

    	rte_exit(EXIT_FAILURE, "Cond not start.\n");
    }

    /*开启混杂模式*/
    rte_eth_promiscuous_enable((uint16_t)gDpdkPortId);
    // rte_exit(EXIT_FAILURE, "Promiscoous failure\n");

}


//打包数据包
static void ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

    // 1. ethdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(&eth->s_addr, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&eth->d_addr, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);       //发送 host to network 两个字节以上都需要转换

    // 2. iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;       //大小端转换 转成网络字节序
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3. udphdr
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    udp->dgram_len = htons(total_len - sizeof(struct rte_ether_hdr) -sizeof(struct rte_ipv4_hdr));
    udp->dgram_cksum = 0;

    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) -sizeof(struct rte_ipv4_hdr);

    rte_memcpy((uint8_t *)(udp+1), data, udplen);  //udp +1 含义  依udp 的头为一个单元向后移动一个单元指向数据存储的起始位置
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);


#ifdef DPDK_DEBUG
        struct in_addr addr;
        addr.s_addr = gSrcIp;
        printf("---> src: %s %u\n",inet_ntoa(addr), ntohs(gSrcPort));

        addr.s_addr = gDstIp;
        printf("---> dst: %s:%u\n",inet_ntoa(addr), ntohs(gDstPort));
#endif
}

/**
@param mbuf_pool 内存池 在内存池中获取 mbuf

*/
struct rte_mbuf *ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length){
    //从rte_mempool 中获取mbuf，使用内存池最小的单位是mbuf
    //udp 报文长度大小       eth+ipv4+udphdr+data    14+20+8+sizeof(data)
    // 使用内存池的时候能用多少就开辟多少，不要开辟无效的内存空间，避免开辟空间过大造成问题。
    const unsigned total_len = length + 42;

    //此时只是把mubf的指针指向内存池中可以开辟内存的位置，开辟实际大小需要在后面设置
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc error!\n");
    }

    mbuf->pkt_len = total_len;    //此处没有必要做细分,和业务相关。把pkt_len 和data_len 设置成一样大就行。
    mbuf->data_len = total_len;

    //mbuf 是个结构体，和实际存储数据的位置不是同一个位置。需要拿到具体存储数据的具体位置。
    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *); //pktdata 指向数据存储的实际位置

    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}


int main(int argc, char *argv[]) {

    /** 1.DPDK EVl Init*/
    if (rte_eal_init(argc, argv) < 0) {

        rte_exit(EXIT_FAILURE, "error with EAL init\n.");
    }

    /*2. DPDk 一个进程里面确定一个进程池,接受数据是由有它接受的*/
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 0, 0,
                                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n.");
    }

    /*3.确定端口在哪里出数据*/
	ng_init_port(mbuf_pool);

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

	while (1){
         /* port_id 接收数据的网络适配器序号(eth0)              queue_id 多队列网卡中对应的那个队列
            rx_pkts  存储接受数据块指针            nb_pkts 可以接受多少个包          */

        struct rte_mbuf *mbufs[BURST_SIZE];  //mbufs 不需要开辟内存，数据是存储到设置接受队列的内存池中

        /* 获取的是以太网数据*/
        unsigned num_recvd =  rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE); // 从内存池中获取的数据
        if ( num_recvd > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "Error receving from eth \n");
        }

        unsigned i = 0;
        for (i = 0 ; i< num_recvd; i++) {
                                            /* m 指取出那块数据        t 转换为那种数据类型*/
            struct rte_ether_hdr *ethdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            //struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            if (ethdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i],
                                        struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

            if(iphdr->next_proto_id == IPPROTO_UDP) {

                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)((unsigned char *)iphdr + sizeof(struct rte_ipv4_hdr));

        #if ENABLE_SEND  //解析六个值
            rte_memcpy(gDstMac, (uint8_t *)ethdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

            rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
            rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

            rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
            rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

        #endif

                uint16_t length = ntohs(udphdr->dgram_len); //网络字节序转换为用户字节序            两个字节以上都需要转换,适配多种环境

                *((char *)udphdr + length) = '\0';

                struct in_addr addr;

                addr.s_addr = iphdr->src_addr;

                printf("src: %s %u\n",inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;

                printf("dst: %s:%u length: %u ,%s \n",inet_ntoa(addr), ntohs(udphdr->dst_port),
                                            length, (char *)(udphdr +1));
       #if ENABLE_SEND
           struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t *)(udphdr +1), length);

           rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);

           rte_pktmbuf_free(txbuf);
       #endif
               rte_pktmbuf_free(mbufs[i]);  //内存中数据使用完毕，在放回到内存池中

            }
        }

    }

    return 0;
}


//开发中遇到问题看是很复杂的问题到了最后基本上都是很简单的问题

