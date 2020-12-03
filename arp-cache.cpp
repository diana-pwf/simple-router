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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>
#include <ctime>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
    // 先记录无效项，然后在handle过程中对无效项返回ICMP消息，处理结束后再删除
    // 防止刚发送第5次还没有回复就被删除了或返回了ICMP
    std::vector<std::_List_iterator<std::shared_ptr<ArpRequest>>> invalidRequests;
    for (auto it = m_arpRequests.begin(); it != m_arpRequests.end(); ++it) {
        if ((*it)->nTimesSent == 5) {
            invalidRequests.push_back(it);
        }
    }

    for (auto arpRequest: m_arpRequests) {
        handleArpRequest(arpRequest);
    }

    for(auto invalidRequest: invalidRequests)
    {
        m_arpRequests.erase(invalidRequest);
    }

    // 先标记无效项并将无效项的指针储存起来再一起删除 避免在迭代过程中删除
    std::vector<std::_List_iterator<std::shared_ptr<ArpEntry>>> invalidEntries;
    for (auto it = m_cacheEntries.begin(); it != m_cacheEntries.end(); ++it) {
        if (!(*it)->isValid) {
            invalidEntries.push_back(it);
        }
    }
    for(auto invalidEntry: invalidEntries)
    {
        m_cacheEntries.erase(invalidEntry);
    }

}

void
ArpCache::handleArpRequest(std::shared_ptr<ArpRequest>& request)
{
    time_point now = steady_clock::now();
    // 判断是否需要重新发送请求
    if (now - request->timeSent > seconds(1))
    {
        if (request->nTimesSent == 5)
        {
            for(auto packet: request->packets)
            {
                // 发送destination host unreachable的ICMP消息
                Buffer replyPacket = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr)));
                auto *pReplyEthernet = (struct ethernet_hdr*)replyPacket.data();
                auto *pEthernet = (struct ethernet_hdr*)packet.packet.data();
                memcpy(pReplyEthernet, pEthernet, sizeof(struct ethernet_hdr));
                memcpy(pReplyEthernet->ether_dhost, pEthernet->ether_shost, ETHER_ADDR_LEN);
                auto *interface = m_router.findIfaceByName(packet.iface);
                memcpy(pReplyEthernet->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
                pReplyEthernet->ether_type = ethertype_ip;

                auto *pReplyIpv4 = (struct ip_hdr*)(replyPacket.data() + sizeof(struct ethernet_hdr));
                auto *pIpv4 = (struct ip_hdr*)(packet.packet.data() + sizeof(struct ethernet_hdr));
                memcpy(pReplyIpv4, pIpv4, sizeof(struct ip_hdr));
                pReplyIpv4->ip_dst = pIpv4->ip_src;
                pReplyIpv4->ip_src = interface->ip;
                pReplyIpv4->ip_p = ip_protocol_icmp;
                pReplyIpv4->ip_id = 0;
                pReplyIpv4->ip_ttl = 64;
                // 疑问：长度这里为什么要进行转换
                pReplyIpv4->ip_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
                pReplyIpv4->ip_sum = 0;
                pReplyIpv4->ip_sum = cksum(pReplyIpv4, sizeof(struct ip_hdr));

                auto *pReplyIcmpT3 = (struct icmp_t3_hdr*)(replyPacket.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
                pReplyIcmpT3->icmp_type = 3;
                pReplyIcmpT3->icmp_code = 1;
                pReplyIcmpT3->unused = 0;
                // 疑问：下面两行是为啥
                pReplyIcmpT3->next_mtu = 0;
                memcpy(pReplyIcmpT3->data, pIpv4, ICMP_DATA_SIZE);
                pReplyIcmpT3->icmp_sum = 0;
                pReplyIcmpT3->icmp_sum = cksum(pReplyIcmpT3, sizeof(struct icmp_t3_hdr));

                m_router.sendPacket(replyPacket, interface->name);
            }
        }
        else
        {
            // 调用m_router的函数发送arp request请求
            Buffer arpRequest = *(new Buffer(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr)));
            auto *pReplyEthernet = (struct ethernet_hdr*)(arpRequest.data());

            const auto routing_entry = m_router.m_routingTable.lookup(request->ip);
            auto *interface = m_router.findIfaceByName(routing_entry.ifName);
            memcpy(pReplyEthernet->ether_shost, interface->addr.data(), ETHER_ADDR_LEN);
            for(unsigned char & i : pReplyEthernet->ether_dhost)
            {
                i = 0xff;
            }
            pReplyEthernet->ether_type = ethertype_arp;

            auto *pReplyArp = (struct arp_hdr*)(arpRequest.data() + sizeof(struct ethernet_hdr));
            pReplyArp->arp_sip = interface->ip;
            pReplyArp->arp_tip = request->ip;
            memcpy(pReplyArp->arp_sha, interface->addr.data(), ETHER_ADDR_LEN);
            for(unsigned char & i : pReplyArp->arp_tha)
            {
                i = 0xff;
            }
            pReplyArp->arp_hrd = htons(arp_hrd_ethernet);
            pReplyArp->arp_pro = htons(ethertype_ip);
            pReplyArp->arp_op = htons(arp_op_request);
            pReplyArp->arp_hln = 0x06;
            pReplyArp->arp_pln = 0x04;
            m_router.sendPacket(arpRequest, routing_entry.ifName);

            request->timeSent = now;
            request->nTimesSent += 1;
        }

    }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
