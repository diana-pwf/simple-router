/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <cstring>


namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;
  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  try{
      // 检查数据包的长度是否小于以太网帧包头长度
      if (packet.size() < sizeof(struct ethernet_hdr)){
          throw std::runtime_error("packet size is too small");
      }
      else{
          auto *pEthernet = (struct ethernet_hdr *)packet.data();
          // 广播地址
          const Buffer broadcastAddr(ETHER_ADDR_LEN, 0xff);
          // 应该由路由器处理的数据包：
          // 以太网帧中的目的MAC地址为 接收端口的MAC地址 或 广播地址
          if (!memcmp(pEthernet->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN)
          || !memcmp(pEthernet->ether_dhost, broadcastAddr.data(), ETHER_ADDR_LEN))
          {
              uint16_t packetType = ntohs(pEthernet->ether_type);
              // 对类型是ARP或Ipv4的数据包进行处理
              if (packetType == ethertype_ip)
              {
                  processIpv4Packet(packet, iface);
              }
              else if(packetType == ethertype_arp)
              {
                  processArpPacket(packet, iface);
              }
              else{
                  throw std::runtime_error("Neither ARP or IP packet received");
              }
              return;
          }
          throw std::runtime_error("Dest Mac addr is neither router interface nor broadcast");
      }
  }
  catch (std::exception& e) {
      std::cerr << e.what() << std::endl;
  }
}

void
SimpleRouter::processArpPacket(const Buffer& packet, const Interface *iface)
{
    // 检查ARP数据包的长度是否刚好为 以太网帧包头长度 + ARP包长度
    if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)){
        throw std::runtime_error("Incorrect ARP size");
    }
    // 检查ARP数据包中的前四项参数是否合法
    auto *pArp = (struct arp_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    if (pArp->arp_hrd != htons(arp_hrd_ethernet)){
        throw std::runtime_error("ARP hardware type is not ethernet");
    }
    if (pArp->arp_pro != htons(ethertype_ip)){
        throw std::runtime_error("ARP protocol type is not ipv4");
    }
    if (pArp->arp_hln != 0x06){
        throw std::runtime_error("ARP hardware address length is incorrect");
    }
    if (pArp->arp_pln != 0x04){
        throw std::runtime_error("ARP protocol address length is incorrect");
    }

    if (pArp->arp_op == htons(arp_op_request)){
        // 处理ARP请求
        // 若ARP包中的目的IP地址为接收到的端口IP 则发送ARP回复
        // ARP回复中：
        // 源MAC地址 --- ARP请求中的目的MAC地址 == 以太网帧包头的目的MAC地址 == 接收到的路由器端口的MAC地址
        // 源IP地址 --- ARP请求中的目的IP地址 == 接收到的路由器端口的IP地址
        // 目的MAC地址 --- ARP请求中的源MAC地址 == 以太网帧包头的源MAC地址
        // 目的IP地址 --- ARP请求中的源IP地址
        if (pArp->arp_tip == iface->ip){
            // 拷贝原请求包并修改相应字段
            sendArpReply(packet, iface);
        }
    }
    else if (pArp->arp_op == htons(arp_op_reply)){
        // 处理ARP回复
        // 若源IP地址在ARP缓存中没有对应的IP-MAC映射表项
        // 获取源IP地址和源Mac地址，作为新表项加入ARP缓存
        processArpReply(packet);
    }
    else{
        throw std::runtime_error("Neither arp request nor arp reply");
    }
}

void
SimpleRouter::sendArpReply(const Buffer &packet, const Interface *iface)
{
    std::cerr << "sendArpreply" << std::endl;

    Buffer arpReplyPacket = packet;
    auto *pReplyEthernet = (struct ethernet_hdr *)arpReplyPacket.data();
    auto *pEthernet = (struct ethernet_hdr *)packet.data();

    memcpy(pReplyEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);
    memcpy(pReplyEthernet->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

    auto *pReplyArp = (struct arp_hdr *)(arpReplyPacket.data() + sizeof(struct ethernet_hdr));
    auto *pArp = (struct arp_hdr *)(packet.data() + sizeof(struct ethernet_hdr));

    memcpy(pReplyArp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
    memcpy(pReplyArp->arp_tha, pArp->arp_sha, ETHER_ADDR_LEN);
    pReplyArp->arp_sip = pArp->arp_tip;
    pReplyArp->arp_tip = pArp->arp_sip;
    pReplyArp->arp_op = htons(arp_op_reply);

    sendPacket(arpReplyPacket, iface->name);
}

void
SimpleRouter::processArpReply(const Buffer &packet)
{
    std::cerr << "processArpreply" << std::endl;
    auto *pArp = (struct arp_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    uint32_t senderIp = pArp->arp_sip;

    if (m_arp.lookup(senderIp) == nullptr){
        Buffer senderMac;
        for (unsigned char & i : pArp->arp_sha) {
            senderMac.push_back(i);
        }

        auto arpRequest = m_arp.insertArpEntry(senderMac, senderIp);

        // 处理相应ARP请求的待发送数据包并将其从队列中移除
        if (arpRequest != nullptr){
            for (const auto& arpPacket: arpRequest->packets){
                handlePacket(arpPacket.packet, arpPacket.iface);
            }
            m_arp.removeRequest(arpRequest);
        }
    }
}

void
SimpleRouter::processIpv4Packet(const Buffer& packet, const Interface *iface)
{
    // 检查IP数据包的长度
    if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr))
    {
        throw std::runtime_error("IP packet size too small");
    }

    // 检查IP数据包的校验和
    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    struct ip_hdr pIpv4_tmp = *pIpv4;
    pIpv4_tmp.ip_sum = 0;
    if (pIpv4->ip_sum != cksum(&pIpv4_tmp, sizeof(struct ip_hdr)))
    {
        throw std::runtime_error("checksum is incorrect");
    }

    // 通过目的IP地址判断是路由器三个端口IP地址之一还是需要转发
    auto* interface = findIfaceByIp(pIpv4->ip_dst);
    if (interface != nullptr)
    {
        // 对协议类型为ICMP的Ipv4数据包，只处理Echo类型 发送Echo reply类型的ICMP包
        // Echo reply中：
        // 目的MAC地址 --- Echo中 源MAC地址 = 查路由表得到的网关对应的MAC = 源IP对应的MAC
        // 目的IP地址 --- Ipv4包头中的源IP地址
        // 源MAC地址 --- 路由表中目的IP地址对应的转发端口的MAC地址
        // 源IP地址 --- 路由表中目的IP地址对应的转发端口的IP地址

        // 可以提炼的前提：
        // 转发数据包的时候 只修改源MAC地址和目的MAC地址 IP地址均不要改动
        // 回复ICMP的时候 如果网关为* 上述结论成立

        if (pIpv4->ip_p == ip_protocol_icmp)
        {

            auto *pIcmp = (struct icmp_hdr *)(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
            if (pIcmp->icmp_type == 8 && !pIcmp->icmp_code)
            {
                // 先查询路由表和ARP缓存，然后拷贝Echo数据包，修改相应字段并发送
                sendIcmpEchoReply(packet, iface);
            }
        }
        else if (pIpv4->ip_p == ip_protocol_tcp || pIpv4->ip_p == ip_protocol_udp)
        {
            // 发送 unreachable的ICMP消息
            sendIcmpDestPortUnreachableReply(packet, iface);
        }
    }
    else
    {
        if (pIpv4->ip_ttl == 1)
        {
            // 发送超时ICMP消息
            sendIcmpTimeExceededReply(packet, iface);
            return;
        }
        else
        {
            // 从路由表中获取下一跳的IP地址 并进行转发
            sendForwardingPacket(packet, iface);
        }
    }
}

void
SimpleRouter::sendIcmpEchoReply(const Buffer &packet, const Interface *iface) {
    std::cerr << "sendIcmpEcho" << std::endl;

    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIpv4->ip_src);
    auto forwardInterface = findIfaceByName(routingEntry.ifName);
    // 查询目的IP地址在ARP缓存中的对应MAC地址
    auto arpEntry = m_arp.lookup(pIpv4->ip_src);
    // 若不存在，则加入请求队列
    if (arpEntry == nullptr){
        // 注意：放进去的是接收端口的名字
        m_arp.queueRequest(pIpv4->ip_src, packet, iface->name);
        return;
    }

    Buffer echoPacket = packet;
    auto *pEchoEthernet = (struct ethernet_hdr *)echoPacket.data();

    memcpy(pEchoEthernet->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
    memcpy(pEchoEthernet->ether_shost, forwardInterface->addr.data(), ETHER_ADDR_LEN);

    auto *pEchoIpv4 = (struct ip_hdr *)(echoPacket.data() + sizeof(struct ethernet_hdr));

    pEchoIpv4->ip_src = forwardInterface->ip;
    pEchoIpv4->ip_dst = pIpv4->ip_src;

    pEchoIpv4->ip_id = 0;
    pEchoIpv4->ip_ttl = 64;
    pEchoIpv4->ip_sum = 0;
    pEchoIpv4->ip_sum = cksum(pEchoIpv4, sizeof(struct ip_hdr));

    auto *pEchoIcmp = (struct icmp_hdr *)(echoPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
    pEchoIcmp->icmp_type = 0;
    pEchoIcmp->icmp_code = 0;
    pEchoIcmp->icmp_sum = 0;

    // 求校验码的时候长度不是icmp_hdr的长度 (因为echo消息会带数据)
    pEchoIcmp->icmp_sum = cksum(pEchoIcmp, packet.size() - sizeof(struct ip_hdr) - sizeof(struct ethernet_hdr));

    sendPacket(echoPacket, forwardInterface->name);
}

void
SimpleRouter::sendIcmpDestPortUnreachableReply(const Buffer& packet, const Interface* iface)
{
    std::cerr << "sendIcmpPortUnreach" << std::endl;

    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    auto routingEntry = m_routingTable.lookup(pIpv4->ip_src);
    auto forwardInterface = findIfaceByName(routingEntry.ifName);
    // 查询目的IP地址在ARP缓存中的对应MAC地址
    auto arpEntry = m_arp.lookup(pIpv4->ip_src);
    // 若不存在，则加入请求队列
    if (arpEntry == nullptr)
    {
        // 注意：放进去的是接收端口的名字
        m_arp.queueRequest(pIpv4->ip_src, packet, iface->name);
        return;
    }

    Buffer replyPacket = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
    auto *pReplyEthernet = (struct ethernet_hdr *)replyPacket.data();
    auto *pEthernet = (struct ethernet_hdr *)packet.data();

    memcpy(pReplyEthernet, pEthernet, sizeof(struct ethernet_hdr));
    memcpy(pReplyEthernet->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
    memcpy(pReplyEthernet->ether_shost, forwardInterface->addr.data(), ETHER_ADDR_LEN);

    auto *pReplyIpv4 = (struct ip_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr));
    memcpy(pReplyIpv4, pIpv4, sizeof(struct ip_hdr));
    pReplyIpv4->ip_src = forwardInterface->ip;
    pReplyIpv4->ip_dst = pIpv4->ip_src;
    pReplyIpv4->ip_id = 0;
    pReplyIpv4->ip_ttl = 64;
    pReplyIpv4->ip_p = ip_protocol_icmp;
    pReplyIpv4->ip_len = htons(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr));
    pReplyIpv4->ip_sum = 0;
    pReplyIpv4->ip_sum = cksum(pReplyIpv4, sizeof(struct ip_hdr));

    auto *pReplyIcmpT3 = (struct icmp_t3_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
    pReplyIcmpT3->icmp_type = 3;
    pReplyIcmpT3->icmp_code = 3;
    pReplyIcmpT3->unused = 0;
    pReplyIcmpT3->next_mtu = 0;
    memcpy(pReplyIcmpT3->data, pIpv4, ICMP_DATA_SIZE);

    pReplyIcmpT3->icmp_sum = 0;
    pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));

    sendPacket(replyPacket, forwardInterface->name);
}

void
SimpleRouter::sendIcmpDestHostUnreachableReply(const Buffer& packet, const std::string& iface)
{
    std::cerr << "sendIcmpHostUnreach" << std::endl;

    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    auto routingEntry = getRoutingTable().lookup(pIpv4->ip_src);
    auto interface = findIfaceByName(routingEntry.ifName);
    // 查询目的IP地址在ARP缓存中的对应MAC地址
    auto arpEntry = m_arp.lookup(pIpv4->ip_src);
    // 若不存在，则加入请求队列
    if (arpEntry == nullptr)
    {
        // 注意：放进去的是接收端口的名字
        m_arp.queueRequest(pIpv4->ip_src, packet, iface);
        return;
    }

    Buffer replyPacket = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
    auto *pReplyEthernet = (struct ethernet_hdr*)replyPacket.data();
    auto *pEthernet = (struct ethernet_hdr*)packet.data();
    memcpy(pReplyEthernet, pEthernet, sizeof(struct ethernet_hdr));

    memcpy(pReplyEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);

    memcpy(pReplyEthernet->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
    pReplyEthernet->ether_type = htons(ethertype_ip);

    auto *pReplyIpv4 = (struct ip_hdr*)(replyPacket.data() + sizeof(struct ethernet_hdr));

    memcpy(pReplyIpv4, pIpv4, sizeof(struct ip_hdr));
    pReplyIpv4->ip_dst = pIpv4->ip_src;
    pReplyIpv4->ip_src = interface->ip;
    pReplyIpv4->ip_p = ip_protocol_icmp;
    pReplyIpv4->ip_id = 0;
    pReplyIpv4->ip_ttl = 64;

    pReplyIpv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
    pReplyIpv4->ip_sum = 0;
    pReplyIpv4->ip_sum = cksum(pReplyIpv4, sizeof(struct ip_hdr));

    auto *pReplyIcmpT3 = (struct icmp_t3_hdr*)(replyPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
    pReplyIcmpT3->icmp_type = 3;
    pReplyIcmpT3->icmp_code = 1;
    pReplyIcmpT3->unused = 0;
    pReplyIcmpT3->next_mtu = 0;
    memcpy(pReplyIcmpT3->data, pIpv4, ICMP_DATA_SIZE);
    pReplyIcmpT3->icmp_sum = 0;
    pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));

    sendPacket(replyPacket, interface->name);
};


void
SimpleRouter::sendIcmpTimeExceededReply(const Buffer& packet, const Interface* iface)
{
    std::cerr << "sendIcmpTimeExceed" << std::endl;
    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));

    auto routingEntry = m_routingTable.lookup(pIpv4->ip_src);
    auto forwardInterface = findIfaceByName(routingEntry.ifName);

    // 查询目的IP地址在ARP缓存中的对应MAC地址
    auto arpEntry = m_arp.lookup(pIpv4->ip_src);

    // 若不存在，则加入请求队列
    if (arpEntry == nullptr)
    {
        // 注意：放进去的是接收端口的名字
        m_arp.queueRequest(pIpv4->ip_src, packet, iface->name);
        return;
    }

    Buffer replyPacket = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
    auto *pReplyEthernet = (struct ethernet_hdr *)replyPacket.data();
    auto *pEthernet = (struct ethernet_hdr *)packet.data();

    memcpy(pReplyEthernet, pEthernet, sizeof(struct ethernet_hdr));
    memcpy(pReplyEthernet->ether_dhost, arpEntry->mac.data(), ETHER_ADDR_LEN);
    memcpy(pReplyEthernet->ether_shost, forwardInterface->addr.data(), ETHER_ADDR_LEN);

    auto *pReplyIpv4 = (struct ip_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr));
    memcpy(pReplyIpv4, pIpv4, sizeof(struct ip_hdr));
    pReplyIpv4->ip_src = forwardInterface->ip;
    pReplyIpv4->ip_dst = pIpv4->ip_src;
    pReplyIpv4->ip_id = 0;
    pReplyIpv4->ip_ttl = 64;
    pReplyIpv4->ip_p = ip_protocol_icmp;
    pReplyIpv4->ip_len = htons(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr));
    pReplyIpv4->ip_sum = 0;
    pReplyIpv4->ip_sum = cksum(pReplyIpv4, sizeof(struct ip_hdr));

    auto *pReplyIcmpT3 = (struct icmp_t3_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
    pReplyIcmpT3->icmp_type = 11;
    pReplyIcmpT3->icmp_code = 0;
    pReplyIcmpT3->unused = 0;
    pReplyIcmpT3->next_mtu = 0;
    memcpy(pReplyIcmpT3->data, pIpv4, ICMP_DATA_SIZE);

    pReplyIcmpT3->icmp_sum = 0;
    pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));

    sendPacket(replyPacket, forwardInterface->name);
}

void
SimpleRouter::sendForwardingPacket(const Buffer& packet, const Interface* iface)
{
    std::cerr << "forwardPacket" << std::endl;
    auto *pIpv4 = (struct ip_hdr *)(packet.data() + sizeof(struct ethernet_hdr));

    auto routingEntry = m_routingTable.lookup(pIpv4->ip_dst);
    auto arp_entry = m_arp.lookup(pIpv4->ip_dst);
    if (arp_entry == nullptr)
    {
        m_arp.queueRequest(pIpv4->ip_dst, packet, iface->name);
        return;
    }
    else
    {
        // 在原有数据包的基础上修改
        Buffer forwardPacket = packet;
        auto *pForwardEthernet = (struct ethernet_hdr *)forwardPacket.data();
        memcpy(pForwardEthernet->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);

        auto forwardInterface = findIfaceByName(routingEntry.ifName);
        memcpy(pForwardEthernet->ether_shost, forwardInterface->addr.data(), ETHER_ADDR_LEN);

        auto *pForwardIpv4 = (struct ip_hdr *)(forwardPacket.data() + sizeof(struct ethernet_hdr));
        pForwardIpv4->ip_ttl -= 1;
        pForwardIpv4->ip_sum = 0;
        pForwardIpv4->ip_sum = cksum(pForwardIpv4, sizeof(struct ip_hdr));

        sendPacket(forwardPacket, routingEntry.ifName);
    }
}

void
SimpleRouter::sendArpRequest(uint32_t ip)
{
    std::cerr << "sendArpRequest" << std::endl;
    Buffer arpRequest = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)));
    auto *pReplyEthernet = (struct ethernet_hdr*)(arpRequest.data());
    const auto routing_entry = getRoutingTable().lookup(ip);
    auto *interface = findIfaceByName(routing_entry.ifName);
    memcpy(pReplyEthernet->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
    for(unsigned char & i : pReplyEthernet->ether_dhost)
    {
        i = 0xff;
    }
    pReplyEthernet->ether_type = htons(ethertype_arp);

    auto *pReplyArp = (struct arp_hdr*)(arpRequest.data() + sizeof(struct ethernet_hdr));
    pReplyArp->arp_sip = interface->ip;
    pReplyArp->arp_tip = ip;
    memcpy(pReplyArp->arp_sha, interface->addr.data(), ETHER_ADDR_LEN);
    for(unsigned char & i : pReplyArp->arp_tha)
    {
        i = 0x00;
    }
    pReplyArp->arp_hrd = htons(arp_hrd_ethernet);
    pReplyArp->arp_pro = htons(ethertype_ip);
    pReplyArp->arp_op = htons(arp_op_request);
    pReplyArp->arp_hln = 0x06;
    pReplyArp->arp_pln = 0x04;

    sendPacket(arpRequest, interface->name);

}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{

  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
