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
    // 打印：从哪个接口获得了多少大小的数据包
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    // 通过接口名字获得收到数据包的路由器的接口对象
  const Interface* iface = findIfaceByName(inIface);
    // 丢弃未知接口发来的数据包
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }
  // 获取路由表
  // std::cerr << getRoutingTable() << std::endl;

  // 如果数据包的长度小于最小长度 就丢弃
    try {
        if (packet.size() < sizeof(struct ethernet_hdr))
        {
            std::cerr << packet.size() << std::endl;
            throw std::runtime_error("packet size is too small");
        }
        else
        {
            struct ethernet_hdr *pEthernet = (struct ethernet_hdr *)packet.data();

            Buffer broadcastAddr(ETHER_ADDR_LEN, 0xff);

            if (!memcmp(pEthernet->ether_dhost, iface->addr.data(), ETHER_ADDR_LEN)
            || !memcmp(pEthernet->ether_dhost, broadcastAddr.data(), ETHER_ADDR_LEN))
            {
                uint16_t packetType = ntohs(pEthernet->ether_type);

                if (packetType == ethertype_ip)
                {
                    std::cerr << "process Ipv4" << std::endl;
                    processIpv4Packet(packet, iface);
                }
                else if(packetType == ethertype_arp)
                {
                    std::cerr << "process Arp" << std::endl;
                    processArpPacket(packet, iface);
                }
                else
                {
                    // 如果类型不是ARP或ipv4 就丢弃
                    throw std::runtime_error("Neither ARP or IP packet received");
                }
                return;
            }
            else
            {
                throw std::runtime_error("Dest Mac addr is neither router interface nor broadcast");
            }

        }
    }
    catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
        return;
    }


    // ipv4
    // 判断长度是否合法
    // 判断校验码
    // 数据报的目的IP地址 是路由器的三个端口之一还是需要转发
        // 是路由器的三个端口之一：只处理协议是ICMP的 其余丢弃 （TODO
        // 需要转发：TTL=1 超时处理
        // 否则在ARP缓存中寻找目的IP地址对应的MAC地址
        // 没有就广播
        // 有就转发 TTL减一 重新计算校验码 改变目的MAC地址和源MAC地址 发送


  // arp

  // 解析目的地址、源地址、数据类型和数据内容

  // 目的地址不是相应接口的mac地址或广播地址 就丢弃


  // FILL THIS IN

}

void
SimpleRouter::processArpPacket(const Buffer& packet, const Interface *iface)
{
    // 检查ARP数据包的长度
    if (packet.size() != sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr))
    {
        throw std::runtime_error("Incorrect ARP size");
    }
    // 检查数据包中的各项参数
    auto *pArp = (struct arp_hdr *)(packet.data() + sizeof(struct ethernet_hdr));
    if (ntohs(pArp->arp_hrd) != arp_hrd_ethernet)
    {
        throw std::runtime_error("ARP hardware type is not ethernet");
    }
    if (ntohs(pArp->arp_pro) != ethertype_ip)
    {
        throw std::runtime_error("ARP protocol type is not ipv4");
    }
    if (pArp->arp_hln != 0x06)
    {
        throw std::runtime_error("ARP hardware address length is incorrect");
    }
    if (pArp->arp_pln != 0x04)
    {
        throw std::runtime_error("ARP protocol address length is incorrect");
    }

    if (ntohs(pArp->arp_op) == 1)
    {
        // 处理ARP请求
        // 对已知IP接口回复其MAC地址 其余忽略
        if (pArp->arp_tip == iface->ip)
        {
            Buffer arpReplyPacket = packet;
            auto *pReplyEthernet = (struct ethernet_hdr *)arpReplyPacket.data();
            auto *pEthernet = (struct ethernet_hdr *)packet.data();
            memcpy(pReplyEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);
            memcpy(pReplyEthernet->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

            auto *pReplyArp = (struct arp_hdr *)(arpReplyPacket.data() + sizeof(struct ethernet_hdr));
            pReplyArp->arp_op = htons(2);
            memcpy(pReplyArp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
            memcpy(pReplyArp->arp_tha, pArp->arp_sha, ETHER_ADDR_LEN);
            pReplyArp->arp_sip = pArp->arp_tip;
            pReplyArp->arp_tip = pArp->arp_sip;

            sendPacket(packet, iface->name);
        }

    }
    else if (ntohs(pArp->arp_op) == 2)
    {
        // 处理ARP回复

        uint32_t senderIp = pArp->arp_sip;

        // 在ARP缓存中无对应ip的表项
        if (m_arp.lookup(senderIp) == nullptr)
        {
            Buffer senderMac;
            for (unsigned char & i : pArp->arp_sha) {
                senderMac.push_back(i);
            }

            // 获取该IP映射到的Mac地址，作为新表项插入
            auto arpRequest = m_arp.insertArpEntry(senderMac, senderIp);

            // 处理相应ARP请求的待发送数据包并将其从队列中移除
            if (arpRequest != nullptr)
            {
                for (const auto& arpPacket: arpRequest->packets)
                {
                    handlePacket(arpPacket.packet, arpPacket.iface);
                }
                m_arp.removeRequest(arpRequest);
            }

        }

    }
    else
    {
        throw std::runtime_error("Neither arp request nor arp reply");
    }

    // 接受IP包
    //
}

//void
//SimpleRouter::sendArpReply(const Buffer &packet, const Interface *iface)
//{
//
//}

void
SimpleRouter::processIpv4Packet(const Buffer& packet, const Interface *iface)
{
    // 检查IP数据包的长度
    if (packet.size() < sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr))
    {
        throw std::runtime_error("IP packet size too small");
    }
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

    // 分辨是发给路由器端口之一的还是需要转发
    auto* interface = findIfaceByIp(pIpv4->ip_dst);
    if (interface != nullptr)
    {
        // 正确处理ICMP数据包，其余丢弃
        if (pIpv4->ip_p == ip_protocol_icmp)
        {
            // TODO:检查ICMP数据包的大小、类型、校验码

            auto *pIcmp = (struct icmp_hdr *)(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
            // 此处只需要处理echo的message
            if (pIcmp->icmp_type == 8 && !pIcmp->icmp_code)
            {
                // 找到路由表中目的IP地址对应应该转发到的端口
                auto routingEntry = m_routingTable.lookup(pIpv4->ip_dst);
                auto forwardInterface = findIfaceByName(routingEntry.ifName);
                // 查询网关地址在ARP缓存中的对应MAC地址
                auto arpEntry = m_arp.lookup(routingEntry.gw);

                // 若不存在，则加入请求队列
                if (arpEntry == nullptr)
                {
                    m_arp.queueRequest(pIpv4->ip_dst, packet, iface->name);
                    return;
                }

                Buffer echoPacket = packet;
                auto *pEchoEthernet = (struct ethernet_hdr *)echoPacket.data();
                auto *pEthernet = (struct ethernet_hdr *)packet.data();

                memcpy(pEchoEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);
                memcpy(pEchoEthernet->ether_shost, pEthernet->ether_dhost, ETHER_ADDR_LEN);

                auto *pEchoIpv4 = (struct ip_hdr *)(echoPacket.data() + sizeof(struct ethernet_hdr));
                auto *pEchoIcmp = (struct icmp_hdr *)(echoPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));

                // 准备Ipv4包头
                pEchoIpv4->ip_src = pIpv4->ip_dst;
                pEchoIpv4->ip_dst = pIpv4->ip_src;
                // 疑问：是在哪里规定的
                pEchoIpv4->ip_id = 0;
                pEchoIpv4->ip_ttl = 64;
                pEchoIpv4->ip_sum = 0;
                pEchoIpv4->ip_sum = cksum(pEchoIpv4, sizeof(struct ip_hdr));

                pEchoIcmp->icmp_type = 0;
                // 以防万一还是加上
                pEchoIcmp->icmp_code = 0;
                pEchoIcmp->icmp_sum = 0;
                // 疑问：求校验码的时候长度为什么不是icmp_hdr的长度
                pEchoIcmp->icmp_sum = cksum(pEchoIcmp, packet.size() - sizeof(struct ip_hdr) - sizeof(struct ethernet_hdr));


                sendPacket(echoPacket, routingEntry.ifName);
            }
        }
        else if (pIpv4->ip_p == ip_protocol_tcp || pIpv4->ip_p == ip_protocol_udp)
        {
            // 发送 unreachable的ICMP消息
            // TODO:检查ICMP数据包的大小、类型、校验码

            // 找到路由表中目的IP地址对应应该转发到的端口
            auto routingEntry = m_routingTable.lookup(pIpv4->ip_dst);
            auto forwardInterface = findIfaceByName(routingEntry.ifName);
            // 查询网关地址在ARP缓存中的对应MAC地址
            auto arpEntry = m_arp.lookup(routingEntry.gw);

            // 若不存在，则加入请求队列
            if (arpEntry == nullptr)
            {
                m_arp.queueRequest(pIpv4->ip_dst, packet, iface->name);
                return;
            }

            Buffer replyPacket = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
            auto *pReplyEthernet = (struct ethernet_hdr *)replyPacket.data();
            auto *pEthernet = (struct ethernet_hdr *)packet.data();

            memcpy(pReplyEthernet, pEthernet, sizeof(struct ethernet_hdr));
            memcpy(pReplyEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);
            memcpy(pReplyEthernet->ether_shost, pEthernet->ether_dhost, ETHER_ADDR_LEN);

            auto *pReplyIpv4 = (struct ip_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr));
            memcpy(pReplyIpv4, pIpv4, sizeof(struct ip_hdr));
            pReplyIpv4->ip_src = pIpv4->ip_dst;
            pReplyIpv4->ip_dst = pIpv4->ip_src;
            pReplyIpv4->ip_id = 0;
            pReplyIpv4->ip_ttl = 64;
            pReplyIpv4->ip_p = ip_protocol_icmp;
            pReplyIpv4->ip_len = sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr);
            pReplyIpv4->ip_sum = 0;
            pReplyIpv4->ip_sum = cksum(pReplyIpv4, sizeof(struct ip_hdr));

            auto *pReplyIcmpT3 = (struct icmp_t3_hdr *)(replyPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
            pReplyIcmpT3->icmp_type = 3;
            pReplyIcmpT3->icmp_code = 3;
            pReplyIcmpT3->unused = 0;
            // 疑问：这个是什么
            pReplyIcmpT3->next_mtu = 0;
            memcpy(pReplyIcmpT3->data, pIpv4, ICMP_DATA_SIZE);
            pReplyIcmpT3->icmp_sum = 0;
            pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));

            sendPacket(replyPacket, routingEntry.ifName);
        }
    }
    else
    {
        // 从路由表中获取下一跳的IP地址 并进行转发
        if (pIpv4->ip_ttl == 1)
        {
            // 发送超时ICMP消息
            return;
        }
        else
        {
            auto routingEntry = m_routingTable.lookup(pIpv4->ip_dst);
            auto arp_entry = m_arp.lookup(routingEntry.gw);
            if (arp_entry == nullptr)
            {
                m_arp.queueRequest(pIpv4->ip_dst, packet, iface->name);
            }
            else
            {
                Buffer forwardPacket = packet;
                auto *pForwardEthernet = (struct ethernet_hdr *)forwardPacket.data();
                memcpy(pForwardEthernet->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);

                auto forwardInterface = findIfaceByIp(pIpv4->ip_dst);
                memcpy(pForwardEthernet->ether_shost, forwardInterface->addr.data(), ETHER_ADDR_LEN);

                auto *pForwardIpv4 = (struct ip_hdr *)(forwardPacket.data() + sizeof(struct ethernet_hdr));
                pForwardIpv4->ip_ttl -= 1;
                pForwardIpv4->ip_sum = 0;
                pForwardIpv4->ip_sum = cksum(pForwardIpv4, sizeof(struct ip_hdr));

                sendPacket(forwardPacket, routingEntry.ifName);
            }
        }
    }
}

//void
//SimpleRouter::replyEchoIcmp(const Buffer &packet, const Interface *iface) {
//
//}

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
