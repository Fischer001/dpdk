

#define NUM_MBUFS (4096 -1)   //要求不去满足2的n次方。注意分配时候 小于4K 放到此处，大于4K 的时候另外去分配空间

#define BURST_SIZE 32

int gDpdkPortId = 0;  //端口的Id

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

//端口初始化
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
	const int num_tx_queues = 0;
    struct rte_eth_conf port_conf = port_conf_default;

	/*配置多队列网卡在dpdk中有多少个可以使用*/
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	/**
	*  0  指的是第零号接受队列
	*  128 随机写的，  每个接受队列的最大接受数量。
	*/
	if ( rte_eth_rx_queue_setup(gDpdkPortId, 0, 128,
		    rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf ) < 0) {

		rte_exit(EXIT_FAILUER, "Cond not setup RX queue.\n");
	}

	/*端口启动*/
	if (rte_eth_dev_start(gDpdkPortId) < 0) {

		rte_exit(EXIT_FAILUER, "Cond not start.\n");

	}


}

int main(int argc, char *argv[]) {

    /** 1.DPDK EVl Init*/
    if (rte_eal_init(argc, argv) < 0) {

        rte_exit(EXIT_FAILURE, "error with EAL init\n.");
    }

    /*2. DPDk 一个进程里面确定一个进程池,接受数据是由有它接受的*/
    struct ret_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,0,0,RTE_MBUF_DEFAULT_BUF_SIZE,rte_socket_id());

    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n.");
    }

    /*3.确定端口在哪里出数据*/
	ng_init_port(mbuf_pool);

	while (1){
         /* port_id 接收数据的网络适配器序号(eth0)              queue_id 多队列网卡中对应的那个队列
            rx_pkts  存储接受数据块指针            nb_pkts 可以接受多少个包          */

        struct rte_mbuf *mbufs[BURST_SIZE];  //mbufs 不需要开辟内存，数据是存储到设置接受队列的内存池中

        /* 获取的是以太网数据*/
        unsigned num_recvd =  rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE); // 从内存池中获取的数据
        if ( num_recvd > BURST_SIZE){
            rte_exit(EXIT_FAILURE, "Error receving from eth \n");
        }

        int i = 0;
        for (i ; i< BURST_SIZE; i++) {
                                            /* m 指取出那块数据        t 转换为那种数据类型*/
            struct rte_ether_hdr * ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i],
                                        struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

            if(iphdr->next_proto_id == IPPROTO_UDP) {

                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + sizeof(struct rte_ipv4_hdr));

                uint16_t lenth = ntohs(udphdr->dgram_len); //网络字节序转换为用户字节序            两个字节以上都需要转换
            }
        }
    }


}
